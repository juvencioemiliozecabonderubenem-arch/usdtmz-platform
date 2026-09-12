// api/admin-withdrawals.js
//
// USDTMZ — API 06
// Central Admin:
// - Tesouraria MZN / USDT
// - FX MZN/USD + USDT/USD
// - Depósito MZN por Pagar (M-Pesa / e-Mola)
// - Depósito MZN manual/banco
// - Depósito USDT TRC-20 verificado na blockchain
// - Conversão MZN -> USDT
// - Liquidez
// - Dashboard
//
// IMPORTANTE:
// - Esta API NÃO expõe secrets ao frontend.
// - Pagar só credita MZN quando o top-up estiver PAID.
// - USDT só é creditado após confirmação on-chain.
// - Não cria API 13.

import { neon } from "@neondatabase/serverless";
import TronWeb from "tronweb";
import {
  createHash,
  createHmac,
  randomBytes,
  timingSafeEqual,
} from "node:crypto";

/* =========================================================
   CONFIG
========================================================= */

const sql = neon(process.env.DATABASE_URL);

const MIN_MZN = 64;
const MAX_MZN = 40000;

const USDT_DECIMALS = 6;

const USDT_CONTRACT =
  process.env.USDT_TRON_CONTRACT ||
  "TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t";

const TRON_HOST =
  process.env.TRON_GRID_HOST ||
  "https://api.trongrid.io";

const USDTMZ_RATE_SPREAD_PERCENT =
  Number(process.env.USDTMZ_RATE_SPREAD_PERCENT || "0");

const FX_CACHE_MS = 60 * 1000;

const ADMIN_COOKIE = "usdtmz_admin_session";

const PAGAR_API_BASE_URL =
  process.env.PAGAR_API_BASE_URL ||
  "https://api.pagar.co.mz/api/v1";

const PAGAR_API_KEY =
  process.env.PAGAR_API_KEY || "";

const PAGAR_SIGNING_SECRET =
  process.env.PAGAR_SIGNING_SECRET || "";

const PAGAR_WEBHOOK_SECRET =
  process.env.PAGAR_WEBHOOK_SECRET || "";

const SOURCE_MN = {
  MPESA: "MPESA_BUSINESS",
  EMOLA: "EMOLA_BUSINESS",
  BANK: "BANK",
  MANUAL: "MANUAL_APPROVED",
};

const ALLOWED_MZN_SOURCES = [
  "MPESA_BUSINESS",
  "EMOLA_BUSINESS",
  "BANK",
  "MANUAL_APPROVED",
];

const ALLOWED_USDT_SOURCES = [
  "USDT_TRON",
  "EXTERNAL_WALLET",
];

/* =========================================================
   FX CACHE
========================================================= */

let fxCache = {
  value: null,
  updatedAt: 0,
};

/* =========================================================
   GENERIC HELPERS
========================================================= */

function json(res, status, body) {
  res.status(status);
  res.setHeader("Content-Type", "application/json; charset=utf-8");
  return res.end(JSON.stringify(body));
}

function ok(res, data = {}) {
  return json(res, 200, {
    success: true,
    data,
  });
}

function fail(res, status, message, extra = {}) {
  return json(res, status, {
    success: false,
    error: message,
    ...extra,
  });
}

function methodNotAllowed(res) {
  return fail(res, 405, "Método não permitido.");
}

function normalizeBody(body) {
  return body && typeof body === "object" ? body : {};
}

function toNumber(value) {
  const n = Number(value);

  if (!Number.isFinite(n)) {
    return null;
  }

  return n;
}

function isValidMznAmount(value) {
  const n = toNumber(value);

  return (
    n !== null &&
    Number.isInteger(n) &&
    n >= MIN_MZN &&
    n <= MAX_MZN
  );
}

function isValidPhone(phone) {
  return /^\d{9}$/.test(String(phone || ""));
}

function normalizePhone(phone) {
  return String(phone || "")
    .replace(/\s+/g, "")
    .replace(/^\+258/, "")
    .replace(/^258/, "");
}

function normalizeTxHash(value) {
  return String(value || "").trim();
}

function generateReference(prefix = "usdtmz") {
  return `${prefix}-${Date.now()}-${randomBytes(6).toString("hex")}`;
}

function safeEqualString(a, b) {
  if (!a || !b) return false;

  const aa = Buffer.from(String(a));
  const bb = Buffer.from(String(b));

  if (aa.length !== bb.length) return false;

  return timingSafeEqual(aa, bb);
}

/* =========================================================
   ADMIN AUTH
========================================================= */

function verifyAdminSession(req) {
  const cookieHeader = req.headers.cookie || "";

  const cookies = {};

  for (const item of cookieHeader.split(";")) {
    const index = item.indexOf("=");

    if (index === -1) continue;

    const key = item.slice(0, index).trim();
    const value = item.slice(index + 1).trim();

    cookies[key] = decodeURIComponent(value);
  }

  const token = cookies[ADMIN_COOKIE];

  if (!token) {
    return null;
  }

  const secret = process.env.ADMIN_SESSION_SECRET;

  if (!secret) {
    return null;
  }

  const parts = token.split(".");

  if (parts.length !== 2) {
    return null;
  }

  const [payloadB64, signature] = parts;

  const expected = createHmac("sha256", secret)
    .update(payloadB64)
    .digest("base64url");

  if (!safeEqualString(signature, expected)) {
    return null;
  }

  let payload;

  try {
    payload = JSON.parse(
      Buffer.from(payloadB64, "base64url").toString("utf8")
    );
  } catch {
    return null;
  }

  if (!payload) {
    return null;
  }

  if (payload.id !== "admin") {
    return null;
  }

  if (!payload.exp || Number(payload.exp) < Date.now()) {
    return null;
  }

  return payload;
}

/* =========================================================
   PAGAR
========================================================= */

function assertPagarConfigured() {
  if (!PAGAR_API_KEY) {
    throw new Error("PAGAR_API_KEY não configurada.");
  }

  if (!PAGAR_SIGNING_SECRET) {
    throw new Error("PAGAR_SIGNING_SECRET não configurada.");
  }
}

async function readPagarResponse(response) {
  let data = {};

  try {
    data = await response.json();
  } catch {
    data = {};
  }

  if (!response.ok) {
    const error = new Error(
      data?.message ||
        data?.safeMessage ||
        "Pedido rejeitado pela Pagar API."
    );

    error.code = data?.error || null;
    error.requestId = data?.requestId || null;
    error.httpStatus = response.status;
    error.pagar = data;

    throw error;
  }

  return data;
}

async function pagarGet(path) {
  assertPagarConfigured();

  const url = PAGAR_API_BASE_URL + path;

  const response = await fetch(url, {
    method: "GET",
    headers: {
      Authorization: `Bearer ${PAGAR_API_KEY}`,
      Accept: "application/json",
    },
  });

  return readPagarResponse(response);
}

async function pagarPost(path, body, idempotencyKey) {
  assertPagarConfigured();

  if (!idempotencyKey) {
    throw new Error("Idempotency-Key da Pagar é obrigatória.");
  }

  const timestamp = Date.now().toString();

  const nonce = randomBytes(18).toString("base64url");

  const rawBody = JSON.stringify(body);

  const bodyHash = createHash("sha256")
    .update(rawBody)
    .digest("hex");

  const url = PAGAR_API_BASE_URL + path;

  const canonicalPath = new URL(url).pathname;

  const canonical = [
    timestamp,
    nonce,
    "POST",
    canonicalPath,
    bodyHash,
  ].join("\n");

  const signature = createHmac(
    "sha256",
    PAGAR_SIGNING_SECRET
  )
    .update(canonical)
    .digest("hex");

  const response = await fetch(url, {
    method: "POST",
    headers: {
      Authorization: `Bearer ${PAGAR_API_KEY}`,
      "Content-Type": "application/json",
      Accept: "application/json",

      "Idempotency-Key": idempotencyKey,

      "X-Pagar-Timestamp": timestamp,
      "X-Pagar-Nonce": nonce,
      "X-Pagar-Signature": `v1=${signature}`,
    },
    body: rawBody,
  });

  return readPagarResponse(response);
}

/* =========================================================
   PAGAR STATUS
========================================================= */

function getPagarTopup(data) {
  return (
    data?.topup ||
    data?.data?.topup ||
    data
  );
}

function getPagarTopupStatus(data) {
  const topup = getPagarTopup(data);

  return String(
    topup?.status ||
      data?.status ||
      ""
  ).toUpperCase();
}

/* =========================================================
   PAGAR — CREATE TREASURY TOP-UP
========================================================= */

async function createPagarTreasuryTopup({
  amountMzn,
  method,
  paymentPhone,
}) {
  if (!isValidMznAmount(amountMzn)) {
    throw new Error(
      `O valor deve ser inteiro entre ${MIN_MZN} e ${MAX_MZN} MZN.`
    );
  }

  const normalizedMethod = String(method || "").toUpperCase();

  if (!["MPESA", "EMOLA"].includes(normalizedMethod)) {
    throw new Error("Método Pagar inválido.");
  }

  const phone = normalizePhone(paymentPhone);

  if (!isValidPhone(phone)) {
    throw new Error(
      "Número de telefone inválido. Use 9 dígitos."
    );
  }

  const reference = generateReference(
    normalizedMethod === "MPESA"
      ? "topup-mpesa"
      : "topup-emola"
  );

  const source =
    normalizedMethod === "MPESA"
      ? SOURCE_MN.MPESA
      : SOURCE_MN.EMOLA;

  /*
   * Primeiro criamos o registro local como PENDING.
   * NÃO adicionamos saldo aqui.
   */
  await sql`
    INSERT INTO transactions (
      user_id,
      type,
      asset,
      amount,
      status,
      reference,
      blockchain_tx_hash,
      created_at
    )
    VALUES (
      ${"admin"},
      ${"DEPOSIT_MZN"},
      ${"MZN"},
      ${amountMzn},
      ${"PENDING"},
      ${reference},
      ${null},
      NOW()
    )
  `;

  try {
    const result = await pagarPost(
      "/wallet/topups",
      {
        reference,
        amountMzn,
        method: normalizedMethod,
        paymentPhone: phone,
      },
      `topup:${reference}`
    );

    const topup = getPagarTopup(result);

    const status = getPagarTopupStatus(result);

    /*
     * Em caso de PAID já na resposta inicial,
     * podemos confirmar imediatamente.
     */
    if (status === "PAID") {
      await confirmPagarTreasuryTopup(reference);
    }

    return {
      success: true,
      reference,
      amountMzn,
      method: normalizedMethod,
      source,
      status,
      pagar: {
        id: topup?.id || null,
        status,
        environment: topup?.environment || null,
        providerTransactionId:
          topup?.providerTransactionId || null,
        paidAt: topup?.paidAt || null,
      },
    };
  } catch (error) {
    /*
     * Se a rede falhar, NÃO marcamos automaticamente como FAILED.
     *
     * O resultado pode ser incerto.
     * A referência permanece no banco e pode ser consultada
     * posteriormente.
     */
    if (
      error?.httpStatus >= 400 &&
      error?.httpStatus < 500
    ) {
      await sql`
        UPDATE transactions
        SET status = ${"FAILED"}
        WHERE reference = ${reference}
          AND status = ${"PENDING"}
      `;
    }

    throw error;
  }
}

/* =========================================================
   PAGAR — CONFIRM TOP-UP
========================================================= */

async function confirmPagarTreasuryTopup(reference) {
  if (!reference) {
    throw new Error("Reference do top-up é obrigatória.");
  }

  const rows = await sql`
    SELECT
      id,
      user_id,
      type,
      asset,
      amount,
      status,
      reference,
      created_at
    FROM transactions
    WHERE reference = ${reference}
      AND type = ${"DEPOSIT_MZN"}
    LIMIT 1
  `;

  if (!rows.length) {
    throw new Error(
      "Depósito Pagar não encontrado no USDTMZ."
    );
  }

  const local = rows[0];

  /*
   * Idempotência local:
   * se já foi confirmado, não creditar novamente.
   */
  if (local.status === "CONFIRMED") {
    return {
      reference,
      status: "PAID",
      alreadyConfirmed: true,
      amountMzn: Number(local.amount),
    };
  }

  const result = await pagarGet(
    `/wallet/topups/by-reference/${encodeURIComponent(
      reference
    )}`
  );

  const topup = getPagarTopup(result);

  const pagarStatus = getPagarTopupStatus(result);

  /*
   * Apenas PAID pode aumentar o saldo.
   */
  if (pagarStatus === "PAID") {
    const amountMzn = Number(local.amount);

    if (!Number.isInteger(amountMzn)) {
      throw new Error(
        "Valor local do depósito Pagar inválido."
      );
    }

    /*
     * Atualização da carteira + transação numa operação SQL.
     *
     * A condição status=PENDING impede crédito duplicado.
     */
    const updated = await sql`
      WITH updated_tx AS (
        UPDATE transactions
        SET status = ${"CONFIRMED"}
        WHERE reference = ${reference}
          AND type = ${"DEPOSIT_MZN"}
          AND status = ${"PENDING"}
        RETURNING amount
      ),
      updated_wallet AS (
        UPDATE wallets
        SET
          balance = balance + (
            SELECT amount
            FROM updated_tx
            LIMIT 1
          ),
          updated_at = NOW(),
          status = ${"ACTIVE"}
        WHERE asset = ${"MZN"}
          AND network = ${"FIAT"}
          AND (
            SELECT COUNT(*)
            FROM updated_tx
          ) = 1
        RETURNING id, balance
      )
      SELECT
        (SELECT COUNT(*) FROM updated_tx) AS tx_updated,
        (SELECT balance FROM updated_wallet LIMIT 1) AS balance
    `;

    const txUpdated = Number(
      updated?.[0]?.tx_updated || 0
    );

    /*
     * Se outra chamada já confirmou primeiro,
     * não devemos repetir o crédito.
     */
    if (txUpdated === 0) {
      const current = await sql`
        SELECT status
        FROM transactions
        WHERE reference = ${reference}
        LIMIT 1
      `;

      return {
        reference,
        status: current?.[0]?.status || "CONFIRMED",
        alreadyConfirmed: true,
        amountMzn,
      };
    }

    return {
      reference,
      status: "PAID",
      confirmed: true,
      amountMzn,
      balance: updated?.[0]?.balance ?? null,
      pagarTopupId: topup?.id || null,
      paidAt: topup?.paidAt || null,
    };
  }

  /*
   * Estados não finais:
   * PENDING / PROCESSING
   */
  if (
    pagarStatus === "PENDING" ||
    pagarStatus === "PROCESSING"
  ) {
    return {
      reference,
      status: pagarStatus,
      confirmed: false,
      amountMzn: Number(local.amount),
      message:
        "Pagamento ainda não confirmado pela Pagar.",
    };
  }

  /*
   * Estados finais sem pagamento.
   */
  if (
    pagarStatus === "FAILED" ||
    pagarStatus === "CANCELLED"
  ) {
    await sql`
      UPDATE transactions
      SET status = ${pagarStatus}
      WHERE reference = ${reference}
        AND status = ${"PENDING"}
    `;

    return {
      reference,
      status: pagarStatus,
      confirmed: false,
      amountMzn: Number(local.amount),
      message:
        "O depósito não foi confirmado pela Pagar.",
    };
  }

  /*
   * RECONCILIATION_REQUIRED nunca deve ser
   * transformado automaticamente em crédito.
   */
  if (pagarStatus === "RECONCILIATION_REQUIRED") {
    return {
      reference,
      status: pagarStatus,
      confirmed: false,
      amountMzn: Number(local.amount),
      message:
        "A Pagar exige reconciliação. Nenhum saldo foi creditado.",
    };
  }

  return {
    reference,
    status: pagarStatus || "UNKNOWN",
    confirmed: false,
    amountMzn: Number(local.amount),
    message:
      "Estado Pagar ainda não reconhecido pelo USDTMZ.",
  };
}

/* =========================================================
   FX
========================================================= */

async function fetchJson(url, options = {}) {
  const response = await fetch(url, {
    ...options,
    headers: {
      Accept: "application/json",
      ...(options.headers || {}),
    },
  });

  if (!response.ok) {
    throw new Error(
      `Fonte externa respondeu ${response.status}.`
    );
  }

  return response.json();
}

async function getUsdMznRate() {
  const africaKey =
    process.env.AFRICA_API_KEY || "";

  /*
   * Fonte 1 — Africa's Talking / Africa API,
   * quando configurada.
   */
  if (africaKey) {
    try {
      const data = await fetchJson(
        "https://api.africastalking.com/version1/rates?currency=MZN",
        {
          headers: {
            apiKey: africaKey,
          },
        }
      );

      const candidate =
        Number(
          data?.data?.usdMzn ||
          data?.usdMzn ||
          data?.rate
        );

      if (
        Number.isFinite(candidate) &&
        candidate > 0
      ) {
        return {
          rate: candidate,
          source: "AFRICA_API",
        };
      }
    } catch {
      // passa para a próxima fonte
    }
  }

  /*
   * Fonte 2 — Frankfurter / ECB
   */
  try {
    const data = await fetchJson(
      "https://api.frankfurter.app/latest?from=USD&to=MZN"
    );

    const rate = Number(
      data?.rates?.MZN
    );

    if (
      Number.isFinite(rate) &&
      rate > 0
    ) {
      return {
        rate,
        source: "FRANKFURTER",
      };
    }
  } catch {
    // passa para próxima fonte
  }

  /*
   * Fonte 3 — MoneyConvert
   */
  try {
    const data = await fetchJson(
      "https://api.moneyconvert.net/latest/USD"
    );

    const rate = Number(
      data?.rates?.MZN
    );

    if (
      Number.isFinite(rate) &&
      rate > 0
    ) {
      return {
        rate,
        source: "MONEYCONVERT",
      };
    }
  } catch {
    // nenhuma fonte disponível
  }

  throw new Error(
    "Não foi possível obter a taxa USD/MZN."
  );
}

async function getUsdtUsdRate() {
  /*
   * Coinbase
   */
  try {
    const data = await fetchJson(
      "https://api.coinbase.com/v2/exchange-rates?currency=USDT"
    );

    const rate = Number(
      data?.data?.rates?.USD
    );

    if (
      Number.isFinite(rate) &&
      rate > 0
    ) {
      return {
        rate,
        source: "COINBASE",
      };
    }
  } catch {
    // próxima
  }

  /*
   * CoinGecko
   */
  try {
    const data = await fetchJson(
      "https://api.coingecko.com/api/v3/simple/price?ids=tether&vs_currencies=usd"
    );

    const rate = Number(
      data?.tether?.usd
    );

    if (
      Number.isFinite(rate) &&
      rate > 0
    ) {
      return {
        rate,
        source: "COINGECKO",
      };
    }
  } catch {
    // nenhuma
  }

  throw new Error(
    "Não foi possível obter a taxa USDT/USD."
  );
}

async function getFxRate() {
  const now = Date.now();

  if (
    fxCache.value &&
    now - fxCache.updatedAt < FX_CACHE_MS
  ) {
    return fxCache.value;
  }

  const [usdMzn, usdtUsd] =
    await Promise.all([
      getUsdMznRate(),
      getUsdtUsdRate(),
    ]);

  const marketRate =
    usdMzn.rate / usdtUsd.rate;

  const spread =
    1 + USDTMZ_RATE_SPREAD_PERCENT / 100;

  const rate =
    marketRate * spread;

  const result = {
    rate,
    marketRate,
    usdMzn: usdMzn.rate,
    usdtUsd: usdtUsd.rate,
    spread: USDTMZ_RATE_SPREAD_PERCENT,
    source: `${usdMzn.source}+${usdtUsd.source}`,
    updatedAt: new Date().toISOString(),
  };

  fxCache = {
    value: result,
    updatedAt: now,
  };

  return result;
}

/* =========================================================
   WALLET HELPERS
========================================================= */

async function getWallet(asset, network) {
  const rows = await sql`
    SELECT
      id,
      wallet_address,
      network,
      asset,
      balance,
      status,
      created_at,
      updated_at,
      user_id
    FROM wallets
    WHERE asset = ${asset}
      AND network = ${network}
    ORDER BY id ASC
    LIMIT 1
  `;

  return rows[0] || null;
}

async function ensureWallet(asset, network) {
  const existing = await getWallet(
    asset,
    network
  );

  if (existing) {
    return existing;
  }

  const rows = await sql`
    INSERT INTO wallets (
      wallet_address,
      network,
      asset,
      balance,
      status,
      created_at,
      updated_at,
      user_id
    )
    VALUES (
      ${null},
      ${network},
      ${asset},
      0,
      ${"ACTIVE"},
      NOW(),
      NOW(),
      ${null}
    )
    RETURNING *
  `;

  return rows[0];
}

/* =========================================================
   MZN DEPOSIT — REGISTER
========================================================= */

async function registerMZNDeposit({
  amount,
  reference,
  source,
}) {
  if (!isValidMznAmount(amount)) {
    throw new Error(
      `O valor deve estar entre ${MIN_MZN} e ${MAX_MZN} MZN.`
    );
  }

  const normalizedSource =
    String(source || "").toUpperCase();

  if (
    !ALLOWED_MZN_SOURCES.includes(
      normalizedSource
    )
  ) {
    throw new Error(
      "Fonte de depósito MZN inválida."
    );
  }

  const ref =
    reference ||
    generateReference("deposit-mzn");

  const existing = await sql`
    SELECT
      id,
      status,
      amount,
      reference
    FROM transactions
    WHERE reference = ${ref}
    LIMIT 1
  `;

  if (existing.length) {
    return {
      alreadyExists: true,
      ...existing[0],
    };
  }

  const rows = await sql`
    INSERT INTO transactions (
      user_id,
      type,
      asset,
      amount,
      status,
      reference,
      blockchain_tx_hash,
      created_at
    )
    VALUES (
      ${"admin"},
      ${"DEPOSIT_MZN"},
      ${"MZN"},
      ${amount},
      ${"PENDING"},
      ${ref},
      ${null},
      NOW()
    )
    RETURNING *
  `;

  return rows[0];
}

/* =========================================================
   MZN DEPOSIT — MANUAL CONFIRM
========================================================= */

async function confirmMZNDeposit(reference) {
  if (!reference) {
    throw new Error(
      "Reference do depósito é obrigatória."
    );
  }

  const wallet = await ensureWallet(
    "MZN",
    "FIAT"
  );

  /*
   * Crédito idempotente.
   */
  const result = await sql`
    WITH updated_tx AS (
      UPDATE transactions
      SET status = ${"CONFIRMED"}
      WHERE reference = ${reference}
        AND type = ${"DEPOSIT_MZN"}
        AND status = ${"PENDING"}
      RETURNING amount
    ),
    updated_wallet AS (
      UPDATE wallets
      SET
        balance = balance + (
          SELECT amount
          FROM updated_tx
          LIMIT 1
        ),
        updated_at = NOW(),
        status = ${"ACTIVE"}
      WHERE id = ${wallet.id}
        AND (
          SELECT COUNT(*)
          FROM updated_tx
        ) = 1
      RETURNING balance
    )
    SELECT
      (SELECT COUNT(*) FROM updated_tx) AS updated,
      (SELECT balance FROM updated_wallet LIMIT 1) AS balance
  `;

  const updated =
    Number(result?.[0]?.updated || 0);

  if (updated === 0) {
    const current = await sql`
      SELECT
        status,
        amount,
        reference
      FROM transactions
      WHERE reference = ${reference}
      LIMIT 1
    `;

    if (!current.length) {
      throw new Error(
        "Depósito não encontrado."
      );
    }

    return {
      alreadyConfirmed: true,
      ...current[0],
      balance: result?.[0]?.balance ?? null,
    };
  }

  return {
    confirmed: true,
    reference,
    balance:
      result?.[0]?.balance ?? null,
  };
}

/* =========================================================
   TRON
========================================================= */

function getTronWeb() {
  const privateKey =
    process.env.TRON_PRIVATE_KEY;

  if (!privateKey) {
    throw new Error(
      "TRON_PRIVATE_KEY não configurada."
    );
  }

  return new TronWeb({
    fullHost: TRON_HOST,
    privateKey,
  });
}

function getTreasuryAddress() {
  const address =
    process.env.TRON_TREASURY_ADDRESS ||
    process.env.TRON_WALLET_ADDRESS;

  if (!address) {
    throw new Error(
      "TRON_TREASURY_ADDRESS não configurado."
    );
  }

  return address;
}

function isValidTronAddress(address) {
  try {
    return TronWeb.isAddress(
      String(address || "")
    );
  } catch {
    return false;
  }
}

async function verifyUsdtTransferOnChain(
  txHash,
  expectedAmount
) {
  const tx = normalizeTxHash(txHash);

  if (!tx) {
    throw new Error(
      "TX hash é obrigatório."
    );
  }

  const treasury =
    getTreasuryAddress();

  if (!isValidTronAddress(treasury)) {
    throw new Error(
      "Endereço da tesouraria TRON inválido."
    );
  }

  const txInfoResponse = await fetch(
    `${TRON_HOST}/wallet/gettransactioninfobyid?value=${encodeURIComponent(
      tx
    )}`
  );

  if (!txInfoResponse.ok) {
    throw new Error(
      "Não foi possível consultar a transação TRON."
    );
  }

  const txInfo =
    await txInfoResponse.json();

  if (
    !txInfo ||
    !txInfo.id
  ) {
    throw new Error(
      "Transação TRON não encontrada."
    );
  }

  if (
    txInfo.receipt?.result &&
    txInfo.receipt.result !== "SUCCESS"
  ) {
    throw new Error(
      "A transação TRON não foi executada com sucesso."
    );
  }

  /*
   * Procuramos o evento Transfer confirmado.
   */
  const eventsResponse =
    await fetch(
      `${TRON_HOST}/v1/transactions/${encodeURIComponent(
        tx
      )}/events?only_confirmed=true`
    );

  if (!eventsResponse.ok) {
    throw new Error(
      "Não foi possível consultar os eventos TRON."
    );
  }

  const eventsData =
    await eventsResponse.json();

  const events =
    Array.isArray(eventsData?.data)
      ? eventsData.data
      : [];

  const transfer = events.find(
    (event) => {
      const contract =
        String(
          event?.contract_address || ""
        );

      const name =
        String(
          event?.event_name || ""
        );

      const result =
        event?.result || {};

      return (
        contract === USDT_CONTRACT &&
        name === "Transfer" &&
        String(
          result?.to || ""
        ) === treasury
      );
    }
  );

  if (!transfer) {
    throw new Error(
      "Não foi encontrado um Transfer de USDT para a tesouraria."
    );
  }

  const result =
    transfer.result || {};

  const rawAmount =
    result.value ??
    result.amount ??
    null;

  if (
    rawAmount === null ||
    rawAmount === undefined
  ) {
    throw new Error(
      "Valor do Transfer USDT não encontrado."
    );
  }

  const actualAmount =
    Number(rawAmount) /
    10 ** USDT_DECIMALS;

  if (
    !Number.isFinite(actualAmount) ||
    actualAmount <= 0
  ) {
    throw new Error(
      "Valor USDT on-chain inválido."
    );
  }

  /*
   * O valor blockchain é a fonte da verdade.
   */
  if (
    expectedAmount !== undefined &&
    expectedAmount !== null
  ) {
    const expected =
      Number(expectedAmount);

    if (
      Number.isFinite(expected) &&
      Math.abs(
        actualAmount - expected
      ) > 0.000001
    ) {
      throw new Error(
        `Valor USDT recebido (${actualAmount}) não corresponde ao valor esperado (${expected}).`
      );
    }
  }

  return {
    txHash: tx,
    amount: actualAmount,
    treasury,
    contract: USDT_CONTRACT,
    confirmed: true,
  };
}

/* =========================================================
   USDT DEPOSIT — REGISTER
========================================================= */

async function registerUSDTDeposit({
  amount,
  txHash,
  reference,
  source,
}) {
  const tx = normalizeTxHash(txHash);

  if (!tx) {
    throw new Error(
      "TX hash do USDT é obrigatório."
    );
  }

  const normalizedSource =
    String(
      source || "USDT_TRON"
    ).toUpperCase();

  if (
    !ALLOWED_USDT_SOURCES.includes(
      normalizedSource
    )
  ) {
    throw new Error(
      "Fonte USDT inválida."
    );
  }

  /*
   * Não confiamos no amount enviado pelo frontend.
   * O amount será confirmado pela blockchain.
   */
  const existingTx = await sql`
    SELECT
      id,
      status,
      amount,
      reference,
      blockchain_tx_hash
    FROM transactions
    WHERE blockchain_tx_hash = ${tx}
    LIMIT 1
  `;

  if (existingTx.length) {
    return {
      alreadyExists: true,
      transaction: existingTx[0],
    };
  }

  const ref =
    reference ||
    generateReference("deposit-usdt");

  /*
   * Primeiro verificamos a blockchain.
   */
  const verified =
    await verifyUsdtTransferOnChain(
      tx,
      amount
    );

  const rows = await sql`
    INSERT INTO transactions (
      user_id,
      type,
      asset,
      amount,
      status,
      reference,
      blockchain_tx_hash,
      created_at
    )
    VALUES (
      ${"admin"},
      ${"DEPOSIT_USDT"},
      ${"USDT"},
      ${verified.amount},
      ${"CONFIRMED"},
      ${ref},
      ${verified.txHash},
      NOW()
    )
    RETURNING *
  `;

  /*
   * Crédito da carteira USDT.
   *
   * O INSERT acima identifica a operação.
   * Se houver erro no crédito, o admin deve reconciliar
   * manualmente antes de qualquer repetição.
   */
  await ensureWallet(
    "USDT",
    "TRON"
  );

  await sql`
    UPDATE wallets
    SET
      balance = balance + ${verified.amount},
      updated_at = NOW(),
      status = ${"ACTIVE"}
    WHERE asset = ${"USDT"}
      AND network = ${"TRON"}
  `;

  return {
    confirmed: true,
    transaction: rows[0],
    blockchain: verified,
  };
}

/* =========================================================
   USDT DEPOSIT — CONFIRM
========================================================= */

async function confirmUSDTDeposit({
  reference,
}) {
  if (!reference) {
    throw new Error(
      "Reference do depósito USDT é obrigatória."
    );
  }

  const rows = await sql`
    SELECT *
    FROM transactions
    WHERE reference = ${reference}
      AND type = ${"DEPOSIT_USDT"}
    LIMIT 1
  `;

  if (!rows.length) {
    throw new Error(
      "Depósito USDT não encontrado."
    );
  }

  return rows[0];
}

/* =========================================================
   CONVERT MZN -> USDT
========================================================= */

async function convertMZNToUSDT(
  amountMzn
) {
  if (!isValidMznAmount(amountMzn)) {
    throw new Error(
      `O valor deve ser inteiro entre ${MIN_MZN} e ${MAX_MZN} MZN.`
    );
  }

  const fx =
    await getFxRate();

  const usdtAmount =
    amountMzn / fx.rate;

  if (
    !Number.isFinite(usdtAmount) ||
    usdtAmount <= 0
  ) {
    throw new Error(
      "Não foi possível calcular o valor USDT."
    );
  }

  /*
   * Fazemos a operação através de uma única
   * instrução SQL para que débito e crédito
   * dependam da mesma condição.
   */
  const reference =
    generateReference(
      "convert-mzn-usdt"
    );

  const result = await sql`
    WITH debit AS (
      UPDATE wallets
      SET
        balance = balance - ${amountMzn},
        updated_at = NOW()
      WHERE asset = ${"MZN"}
        AND network = ${"FIAT"}
        AND balance >= ${amountMzn}
      RETURNING id
    ),
    credit AS (
      UPDATE wallets
      SET
        balance = balance + ${usdtAmount},
        updated_at = NOW(),
        status = ${"ACTIVE"}
      WHERE asset = ${"USDT"}
        AND network = ${"TRON"}
        AND (
          SELECT COUNT(*)
          FROM debit
        ) = 1
      RETURNING id, balance
    )
    SELECT
      (SELECT COUNT(*) FROM debit) AS debited,
      (SELECT COUNT(*) FROM credit) AS credited,
      (SELECT balance FROM credit LIMIT 1) AS usdt_balance
  `;

  const debited =
    Number(result?.[0]?.debited || 0);

  const credited =
    Number(result?.[0]?.credited || 0);

  if (
    debited !== 1 ||
    credited !== 1
  ) {
    throw new Error(
      "Saldo MZN insuficiente ou carteira USDT não disponível. Conversão cancelada."
    );
  }

  /*
   * Ledger da conversão.
   */
  await sql`
    INSERT INTO transactions (
      user_id,
      type,
      asset,
      amount,
      status,
      reference,
      blockchain_tx_hash,
      created_at
    )
    VALUES (
      ${"admin"},
      ${"CONVERSION"},
      ${"USDT"},
      ${usdtAmount},
      ${"CONFIRMED"},
      ${reference},
      ${null},
      NOW()
    )
  `;

  return {
    reference,
    amountMzn,
    usdtAmount,
    rate: fx.rate,
    marketRate: fx.marketRate,
    usdMzn: fx.usdMzn,
    usdtUsd: fx.usdtUsd,
    spread: fx.spread,
    source: fx.source,
    usdtBalance:
      result?.[0]?.usdt_balance ?? null,
  };
}

/* =========================================================
   RELEASE RESERVATION
========================================================= */

async function releaseReservation(
  amountUsdt,
  reference
) {
  const amount =
    Number(amountUsdt);

  if (
    !Number.isFinite(amount) ||
    amount <= 0
  ) {
    throw new Error(
      "Quantidade USDT inválida."
    );
  }

  const ref =
    reference ||
    generateReference(
      "release-reservation"
    );

  /*
   * A implementação da reserva deve ser feita
   * apenas sobre saldo reservado existente.
   */
  const rows = await sql`
    SELECT
      id,
      balance
    FROM wallets
    WHERE asset = ${"USDT"}
      AND network = ${"TRON"}
    LIMIT 1
  `;

  if (!rows.length) {
    throw new Error(
      "Carteira USDT não encontrada."
    );
  }

  await sql`
    INSERT INTO transactions (
      user_id,
      type,
      asset,
      amount,
      status,
      reference,
      blockchain_tx_hash,
      created_at
    )
    VALUES (
      ${"admin"},
      ${"RESERVATION_RELEASE"},
      ${"USDT"},
      ${amount},
      ${"CONFIRMED"},
      ${ref},
      ${null},
      NOW()
    )
  `;

  return {
    reference: ref,
    amountUsdt: amount,
    released: true,
  };
}

/* =========================================================
   LIQUIDITY SOURCES
========================================================= */

async function getLiquiditySources() {
  return [
    {
      source: "MPESA_BUSINESS",
      asset: "MZN",
      type: "FIAT",
      status:
        PAGAR_API_KEY
          ? "CONFIGURED"
          : "NOT_CONFIGURED",
    },
    {
      source: "EMOLA_BUSINESS",
      asset: "MZN",
      type: "FIAT",
      status:
        PAGAR_API_KEY
          ? "CONFIGURED"
          : "NOT_CONFIGURED",
    },
    {
      source: "BANK",
      asset: "MZN",
      type: "FIAT",
      status: "MANUAL",
    },
    {
      source: "USDT_TRON",
      asset: "USDT",
      type: "TRON",
      status:
        process.env.TRON_TREASURY_ADDRESS
          ? "CONFIGURED"
          : "NOT_CONFIGURED",
    },
    {
      source: "EXTERNAL_WALLET",
      asset: "USDT",
      type: "TRON",
      status: "MANUAL",
    },
    {
      source: "LIQUIDITY_PARTNER",
      asset: "USDT",
      type: "PARTNER",
      status: "MANUAL",
    },
    {
      source: "MANUAL_APPROVED",
      asset: "MZN",
      type: "FIAT",
      status: "MANUAL",
    },
  ];
}

/* =========================================================
   PENDING DEPOSITS
========================================================= */

async function getPendingDeposits() {
  return sql`
    SELECT
      id,
      user_id,
      type,
      asset,
      amount,
      status,
      reference,
      blockchain_tx_hash,
      created_at
    FROM transactions
    WHERE status = ${"PENDING"}
    ORDER BY created_at DESC
    LIMIT 100
  `;
}

/* =========================================================
   REGISTER FUNDING
========================================================= */

async function registerFunding({
  asset,
  amount,
  reference,
  source,
}) {
  const normalizedAsset =
    String(asset || "").toUpperCase();

  const numericAmount =
    Number(amount);

  if (
    !["MZN", "USDT"].includes(
      normalizedAsset
    )
  ) {
    throw new Error(
      "Asset de funding inválido."
    );
  }

  if (
    !Number.isFinite(numericAmount) ||
    numericAmount <= 0
  ) {
    throw new Error(
      "Valor de funding inválido."
    );
  }

  const ref =
    reference ||
    generateReference("funding");

  const rows = await sql`
    INSERT INTO transactions (
      user_id,
      type,
      asset,
      amount,
      status,
      reference,
      blockchain_tx_hash,
      created_at
    )
    VALUES (
      ${"admin"},
      ${"FUNDING"},
      ${normalizedAsset},
      ${numericAmount},
      ${"PENDING"},
      ${ref},
      ${null},
      NOW()
    )
    RETURNING *
  `;

  return {
    ...rows[0],
    source:
      source || "MANUAL_APPROVED",
  };
}

/* =========================================================
   DASHBOARD
========================================================= */

async function getDashboard() {
  const mznWallet =
    await getWallet(
      "MZN",
      "FIAT"
    );

  const usdtWallet =
    await getWallet(
      "USDT",
      "TRON"
    );

  const trxAddress =
    process.env.TRON_TREASURY_ADDRESS ||
    process.env.TRON_WALLET_ADDRESS ||
    null;

  const [transactions, orders] =
    await Promise.all([
      sql`
        SELECT
          id,
          user_id,
          type,
          asset,
          amount,
          status,
          reference,
          blockchain_tx_hash,
          created_at
        FROM transactions
        ORDER BY created_at DESC
        LIMIT 30
      `,
      sql`
        SELECT
          id,
          order_id,
          name,
          phone,
          operation,
          payment,
          amount,
          usdt_amount,
          rate,
          status,
          created_at,
          mpesa_transaction_id,
          blockchain_tx_hash,
          wallet_address,
          updated_at,
          emola_transaction_id,
          pagar_payment_id,
          pagar_event_id
        FROM orders
        ORDER BY created_at DESC
        LIMIT 30
      `,
    ]);

  const mzn =
    Number(
      mznWallet?.balance || 0
    );

  const usdt =
    Number(
      usdtWallet?.balance || 0
    );

  return {
    treasury: {
      mzn,
      usdt,
      trx: 0,
      reserved_usdt: 0,
      available_usdt: usdt,
      liquidity:
        usdt > 0
          ? "AVAILABLE"
          : "SEM LIQUIDEZ",
    },

    wallets: {
      mzn: mznWallet,
      usdt: usdtWallet,
      trxAddress,
    },

    pagar: {
      configured:
        Boolean(
          PAGAR_API_KEY &&
          PAGAR_SIGNING_SECRET
        ),
      apiBaseUrl:
        PAGAR_API_BASE_URL,
      methods: [
        "MPESA",
        "EMOLA",
      ],
    },

    transactions,
    orders,

    config: {
      minMzn: MIN_MZN,
      maxMzn: MAX_MZN,
      usdtContract:
        USDT_CONTRACT,
      tronHost: TRON_HOST,
      spreadPercent:
        USDTMZ_RATE_SPREAD_PERCENT,
    },
  };
}

/* =========================================================
   ACTIONS
========================================================= */

async function handleAction(
  req,
  res,
  action,
  body
) {
  switch (action) {
    /* -----------------------------------------
       SOURCES
    ----------------------------------------- */
    case "sources":
    case "liquidity_sources": {
      return ok(
        res,
        await getLiquiditySources()
      );
    }

    /* -----------------------------------------
       RATE
    ----------------------------------------- */
    case "rate":
    case "exchange_rate":
    case "fx_rate": {
      try {
        const rate =
          await getFxRate();

        return ok(res, rate);
      } catch (error) {
        return fail(
          res,
          503,
          error.message
        );
      }
    }

    /* -----------------------------------------
       DASHBOARD
    ----------------------------------------- */
    case "dashboard": {
      return ok(
        res,
        await getDashboard()
      );
    }

    /* -----------------------------------------
       PAGAR CREATE TOPUP
    ----------------------------------------- */
    case "create_pagar_treasury_topup":
    case "pagar_treasury_topup": {
      const amountMzn =
        Number(
          body.amount_mzn ??
            body.amount
        );

      const method =
        String(
          body.method || ""
        ).toUpperCase();

      const paymentPhone =
        normalizePhone(
          body.payment_phone ??
            body.paymentPhone ??
            body.phone
        );

      try {
        const result =
          await createPagarTreasuryTopup({
            amountMzn,
            method,
            paymentPhone,
          });

        return ok(
          res,
          result
        );
      } catch (error) {
        console.error(
          "Pagar topup error:",
          error
        );

        return fail(
          res,
          error.httpStatus || 400,
          error.message,
          {
            code:
              error.code || null,
            requestId:
              error.requestId || null,
          }
        );
      }
    }

    /* -----------------------------------------
       PAGAR CHECK TOPUP
    ----------------------------------------- */
    case "confirm_pagar_treasury_topup":
    case "pagar_treasury_topup_status":
    case "check_pagar_treasury_topup": {
      const reference =
        String(
          body.reference || ""
        ).trim();

      try {
        const result =
          await confirmPagarTreasuryTopup(
            reference
          );

        return ok(
          res,
          result
        );
      } catch (error) {
        console.error(
          "Pagar topup status error:",
          error
        );

        return fail(
          res,
          error.httpStatus || 400,
          error.message,
          {
            code:
              error.code || null,
            requestId:
              error.requestId || null,
          }
        );
      }
    }

    /* -----------------------------------------
       MZN REGISTER
    ----------------------------------------- */
    case "register_mzn_deposit": {
      try {
        const result =
          await registerMZNDeposit({
            amount:
              Number(
                body.amount
              ),
            reference:
              body.reference,
            source:
              body.source,
          });

        return ok(
          res,
          result
        );
      } catch (error) {
        return fail(
          res,
          400,
          error.message
        );
      }
    }

    /* -----------------------------------------
       MZN CONFIRM
    ----------------------------------------- */
    case "confirm_mzn_deposit": {
      try {
        const result =
          await confirmMZNDeposit(
            String(
              body.reference || ""
            ).trim()
          );

        return ok(
          res,
          result
        );
      } catch (error) {
        return fail(
          res,
          400,
          error.message
        );
      }
    }

    /* -----------------------------------------
       USDT REGISTER
    ----------------------------------------- */
    case "register_usdt_deposit": {
      try {
        const result =
          await registerUSDTDeposit({
            amount:
              body.amount,
            txHash:
              body.tx_hash ??
              body.txHash,
            reference:
              body.reference,
            source:
              body.source ||
              "USDT_TRON",
          });

        return ok(
          res,
          result
       
