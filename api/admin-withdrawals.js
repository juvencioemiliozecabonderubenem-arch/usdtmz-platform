// api/admin-withdrawals.js
// USDTMZ — Central Admin
// Tesouraria, depósitos, conversão, FX real, Pagar M-Pesa/eMola,
// depósitos USDT TRC20 e fontes de liquidez.
//
// IMPORTANTE:
// - Toda esta API exige sessão ADMIN.
// - Secrets ficam somente nas variáveis de ambiente.
// - Nunca creditar MZN Pagar sem status PAID.
// - Nunca creditar USDT sem verificar a blockchain TRON.
// - Nunca usar PROCESSING/PAID como status de orders.
// - Não criar API 13.

import { neon } from "@neondatabase/serverless";
import { createHmac, timingSafeEqual, randomBytes } from "node:crypto";
import { TronWeb } from "tronweb";

const sql = neon(process.env.DATABASE_URL);

const COOKIE_NAME = "usdtmz_admin_session";

const MIN_MZN = 64;
const MAX_MZN = 40000;

const USDT_CONTRACT =
  process.env.USDT_TRON_CONTRACT ||
  "TR7NHqKQxGTCi8q8ZY4pL8otSzgjLj6t";

const USDT_DECIMALS = 6;

const RATE_SPREAD_PERCENT = Number(
  process.env.USDTMZ_RATE_SPREAD_PERCENT || 0
);

const SOURCES = [
  "MPESA_BUSINESS",
  "EMOLA_BUSINESS",
  "BANK",
  "USDT_TRON",
  "EXTERNAL_WALLET",
  "USDT_PURCHASE",
  "LIQUIDITY_PARTNER",
  "MANUAL_APPROVED",
];

const PAGAR_API_BASE_URL =
  process.env.PAGAR_API_BASE_URL ||
  "https://api.pagar.co.mz/api/v1";

const TRON_HOST = "https://api.trongrid.io";

const RATE_CACHE_MS = 60 * 1000;

let rateCache = null;

// -----------------------------------------------------------------------------
// BASIC HELPERS
// -----------------------------------------------------------------------------

function json(res, status, body) {
  res.status(status);
  res.setHeader("Content-Type", "application/json; charset=utf-8");
  res.setHeader("Cache-Control", "no-store");
  return res.end(JSON.stringify(body));
}

function safeCompare(a, b) {
  if (typeof a !== "string" || typeof b !== "string") return false;

  const aa = Buffer.from(a);
  const bb = Buffer.from(b);

  if (aa.length !== bb.length) return false;

  return timingSafeEqual(aa, bb);
}

function parseCookies(req) {
  const header = req.headers?.cookie || "";
  const cookies = {};

  for (const item of header.split(";")) {
    const index = item.indexOf("=");

    if (index === -1) continue;

    const key = item.slice(0, index).trim();
    const value = item.slice(index + 1).trim();

    cookies[key] = decodeURIComponent(value);
  }

  return cookies;
}

function verifyAdminSession(req) {
  const cookies = parseCookies(req);
  const token = cookies[COOKIE_NAME];

  if (!token) return null;

  const secret = process.env.ADMIN_SESSION_SECRET;

  if (!secret) return null;

  const parts = token.split(".");

  if (parts.length !== 2) return null;

  const [payloadEncoded, signature] = parts;

  const expected = createHmac("sha256", secret)
    .update(payloadEncoded)
    .digest("base64url");

  if (!safeCompare(signature, expected)) {
    return null;
  }

  let payload;

  try {
    payload = JSON.parse(
      Buffer.from(payloadEncoded, "base64url").toString("utf8")
    );
  } catch {
    return null;
  }

  if (!payload) return null;

  if (payload.id !== "admin") return null;

  if (!payload.email) return null;

  if (!Number.isFinite(Number(payload.exp))) return null;

  if (Number(payload.exp) <= Date.now()) return null;

  return payload;
}

function requireAdmin(req) {
  const admin = verifyAdminSession(req);

  if (!admin) {
    const error = new Error("Não autenticado como administrador.");
    error.statusCode = 401;
    throw error;
  }

  return admin;
}

function makeReference(prefix = "TREASURY") {
  const random = randomBytes(8).toString("hex").toUpperCase();

  return `${prefix}-${Date.now()}-${random}`;
}

function normalizeSource(value) {
  return String(value || "")
    .trim()
    .toUpperCase();
}

function isValidSource(value) {
  return SOURCES.includes(normalizeSource(value));
}

function validTronAddress(address) {
  if (!address) return false;

  try {
    return TronWeb.isAddress(String(address).trim());
  } catch {
    return false;
  }
}

function getTreasuryAddress() {
  const address = String(
    process.env.TREASURY_TRON_ADDRESS ||
      process.env.TRON_TREASURY_ADDRESS ||
      ""
  ).trim();

  if (!validTronAddress(address)) {
    throw new Error(
      "TREASURY_TRON_ADDRESS/TRON_TREASURY_ADDRESS não configurado ou inválido."
    );
  }

  return address;
}

function getTronWeb() {
  const apiKey = process.env.TRON_PRO_API_KEY;

  const options = {
    fullHost: TRON_HOST,
  };

  if (apiKey) {
    options.headers = {
      "TRON-PRO-API-KEY": apiKey,
    };
  }

  return new TronWeb(options);
}

function roundMoney(value, decimals = 6) {
  const number = Number(value);

  if (!Number.isFinite(number)) return 0;

  const factor = 10 ** decimals;

  return Math.round(number * factor) / factor;
}

function positiveNumber(value) {
  const number = Number(value);

  if (!Number.isFinite(number) || number <= 0) {
    return null;
  }

  return number;
}

function positiveInteger(value) {
  const number = Number(value);

  if (!Number.isInteger(number) || number <= 0) {
    return null;
  }

  return number;
}

async function fetchJson(url, options = {}, timeoutMs = 10000) {
  const controller = new AbortController();

  const timeout = setTimeout(() => {
    controller.abort();
  }, timeoutMs);

  try {
    const response = await fetch(url, {
      ...options,
      signal: controller.signal,
    });

    const text = await response.text();

    let data;

    try {
      data = text ? JSON.parse(text) : {};
    } catch {
      data = {
        raw: text,
      };
    }

    if (!response.ok) {
      const error = new Error(
        data?.message ||
          data?.error ||
          `HTTP ${response.status}`
      );

      error.status = response.status;
      error.data = data;

      throw error;
    }

    return data;
  } finally {
    clearTimeout(timeout);
  }
}

// -----------------------------------------------------------------------------
// PAGAR
// -----------------------------------------------------------------------------

function pagarConfigured() {
  return Boolean(
    process.env.PAGAR_API_KEY &&
      process.env.PAGAR_SIGNING_SECRET
  );
}

function pagarGetHeaders() {
  const apiKey = process.env.PAGAR_API_KEY;

  if (!apiKey) {
    throw new Error("PAGAR_API_KEY não configurada.");
  }

  return {
    Authorization: `Bearer ${apiKey}`,
    Accept: "application/json",
  };
}

async function pagarGet(path) {
  if (!pagarConfigured()) {
    throw new Error(
      "Pagar não configurado. Defina PAGAR_API_KEY e PAGAR_SIGNING_SECRET."
    );
  }

  const url = `${PAGAR_API_BASE_URL}${path}`;

  return fetchJson(
    url,
    {
      method: "GET",
      headers: pagarGetHeaders(),
    },
    15000
  );
}

async function pagarPost(path, body, idempotencyKey) {
  const apiKey = process.env.PAGAR_API_KEY;
  const signingSecret = process.env.PAGAR_SIGNING_SECRET;

  if (!apiKey || !signingSecret) {
    throw new Error(
      "Pagar não configurado. Defina PAGAR_API_KEY e PAGAR_SIGNING_SECRET."
    );
  }

  const timestamp = Date.now().toString();

  const nonce = randomBytes(18).toString("base64url");

  const rawBody = JSON.stringify(body);

  const bodyHash = createHmac("sha256", "")
    .update(rawBody)
    .digest("hex");

  const url = `${PAGAR_API_BASE_URL}${path}`;

  const canonicalPath = new URL(url).pathname;

  const canonical = [
    timestamp,
    nonce,
    "POST",
    canonicalPath,
    bodyHash,
  ].join("\n");

  const signature = createHmac("sha256", signingSecret)
    .update(canonical)
    .digest("hex");

  return fetchJson(
    url,
    {
      method: "POST",
      headers: {
        Authorization: `Bearer ${apiKey}`,
        "Content-Type": "application/json",
        Accept: "application/json",
        "Idempotency-Key": idempotencyKey,
        "X-Pagar-Timestamp": timestamp,
        "X-Pagar-Nonce": nonce,
        "X-Pagar-Signature": `v1=${signature}`,
      },
      body: rawBody,
    },
    20000
  );
}

async function createPagarTreasuryTopup(body) {
  if (!pagarConfigured()) {
    throw new Error(
      "Pagar não configurado. Configure PAGAR_API_KEY e PAGAR_SIGNING_SECRET."
    );
  }

  const amountMzn = positiveInteger(body.amount_mzn);

  if (!amountMzn) {
    throw new Error("amount_mzn deve ser um número inteiro positivo.");
  }

  if (amountMzn < 20 || amountMzn > 40000) {
    throw new Error(
      "Top-up Pagar deve estar entre 20 e 40000 MZN."
    );
  }

  const method = String(body.method || "")
    .trim()
    .toUpperCase();

  if (!["MPESA", "EMOLA"].includes(method)) {
    throw new Error("Método Pagar inválido. Use MPESA ou EMOLA.");
  }

  const paymentPhone = String(body.payment_phone || "")
    .replace(/\D/g, "");

  if (!/^[0-9]{9}$/.test(paymentPhone)) {
    throw new Error(
      "payment_phone deve conter exatamente 9 dígitos."
    );
  }

  const reference =
    String(body.reference || "").trim() ||
    makeReference("PAGAR-TOPUP");

  if (!/^[A-Za-z0-9._:-]{3,100}$/.test(reference)) {
    throw new Error("Reference inválida.");
  }

  // Registra localmente como PENDING antes de chamar a Pagar.
  // Se já existir a mesma referência, não criamos outra operação.
  const existing = await sql`
    SELECT id, status, reference, amount
    FROM transactions
    WHERE reference = ${reference}
    ORDER BY id DESC
    LIMIT 1
  `;

  if (existing.length) {
    const row = existing[0];

    if (row.status === "COMPLETED") {
      return {
        success: true,
        alreadyCompleted: true,
        reference,
        transaction: row,
      };
    }

    if (row.status === "PENDING") {
      // Não duplicar top-up.
      return {
        success: true,
        alreadyPending: true,
        reference,
        transaction: row,
      };
    }
  }

  await sql`
    INSERT INTO transactions
      (
        user_id,
        type,
        asset,
        amount,
        status,
        reference,
        created_at
      )
    VALUES
      (
        'ADMIN',
        'DEPOSIT_MZN',
        'MZN',
        ${amountMzn},
        'PENDING',
        ${reference},
        NOW()
      )
  `;

  let pagarResponse;

  try {
    pagarResponse = await pagarPost(
      "/wallet/topups",
      {
        reference,
        amountMzn: amountMzn,
        method,
        paymentPhone,
      },
      `topup:${reference}`
    );
  } catch (error) {
    await sql`
      UPDATE transactions
      SET
        status = 'FAILED'
      WHERE reference = ${reference}
        AND status = 'PENDING'
    `;

    throw error;
  }

  const topup =
    pagarResponse?.topup ||
    pagarResponse?.data?.topup ||
    pagarResponse?.data ||
    null;

  const status = String(
    topup?.status ||
      pagarResponse?.status ||
      ""
  ).toUpperCase();

  // NUNCA considerar HTTP 202 como PAID.
  if (status === "PAID") {
    const confirmation = await confirmMZNDeposit({
      reference,
      pagar_status: "PAID",
      pagar_payment_id: topup?.id || null,
    });

    return {
      success: true,
      status: "PAID",
      confirmed: true,
      reference,
      pagar: pagarResponse,
      confirmation,
    };
  }

  if (
    status === "FAILED" ||
    status === "CANCELLED"
  ) {
    await sql`
      UPDATE transactions
      SET
        status = 'FAILED'
      WHERE reference = ${reference}
        AND status = 'PENDING'
    `;

    return {
      success: true,
      status,
      confirmed: false,
      reference,
      pagar: pagarResponse,
    };
  }

  return {
    success: true,
    status: status || "PROCESSING",
    confirmed: false,
    reference,
    pagar: pagarResponse,
    message:
      "Top-up aceito pela Pagar. O saldo só será creditado quando o estado for PAID.",
  };
}

async function checkPagarTreasuryTopup(body) {
  const reference = String(body.reference || "").trim();

  if (!reference) {
    throw new Error("reference é obrigatória.");
  }

  const pagarResponse = await pagarGet(
    `/wallet/topups/by-reference/${encodeURIComponent(reference)}`
  );

  const topup =
    pagarResponse?.topup ||
    pagarResponse?.data?.topup ||
    pagarResponse?.data ||
    null;

  const status = String(
    topup?.status ||
      pagarResponse?.status ||
      ""
  ).toUpperCase();

  if (status === "PAID") {
    const confirmation = await confirmMZNDeposit({
      reference,
      pagar_status: "PAID",
      pagar_payment_id: topup?.id || null,
    });

    return {
      success: true,
      status: "PAID",
      confirmed: true,
      reference,
      pagar: pagarResponse,
      confirmation,
    };
  }

  if (
    status === "FAILED" ||
    status === "CANCELLED"
  ) {
    await sql`
      UPDATE transactions
      SET
        status = 'FAILED'
      WHERE reference = ${reference}
        AND status = 'PENDING'
    `;

    return {
      success: true,
      status,
      confirmed: false,
      reference,
      pagar: pagarResponse,
    };
  }

  return {
    success: true,
    status: status || "PROCESSING",
    confirmed: false,
    reference,
    pagar: pagarResponse,
  };
}

// -----------------------------------------------------------------------------
// FX ENGINE
// -----------------------------------------------------------------------------

function parsePositiveRate(value) {
  const number = Number(value);

  if (!Number.isFinite(number) || number <= 0) {
    return null;
  }

  return number;
}

// -----------------------------------------------------------------------------
// PRIMARY FX SOURCE
// Open ER-API
// -----------------------------------------------------------------------------

async function getUsdMznFromOpenERApi() {
  const url =
    "https://open.er-api.com/v6/latest/USD";

  const data = await fetchJson(
    url,
    {
      method: "GET",
      headers: {
        Accept: "application/json",
      },
    },
    10000
  );

  if (data?.result !== "success") {
    throw new Error("Open ER-API retornou erro.");
  }

  const rate = parsePositiveRate(
    data?.rates?.MZN
  );

  if (!rate) {
    throw new Error(
      "Open ER-API não retornou USD/MZN."
    );
  }

  return {
    rate,
    source: "OpenER-API",
    updatedAt:
      data?.time_last_update_utc ||
      new Date().toISOString(),
  };
}

// -----------------------------------------------------------------------------
// FALLBACK FX — AFRICA API
// -----------------------------------------------------------------------------

async function getUsdMznFromAfricaApi() {
  const apiKey = process.env.AFRICA_API_KEY;

  if (!apiKey) {
    throw new Error("AFRICA_API_KEY não configurada.");
  }

  const url =
    "https://api.africa-api.com/v1/data" +
    "?country_code=MZ" +
    "&metric_key=official_exchange_rate_latest_lcu_per_usd" +
    "&latest=true";

  const data = await fetchJson(
    url,
    {
      method: "GET",
      headers: {
        Accept: "application/json",
        Authorization: `Bearer ${apiKey}`,
        "X-API-Key": apiKey,
      },
    },
    10000
  );

  let rate =
    data?.data?.value ??
    data?.data?.rate ??
    data?.value ??
    data?.rate;

  if (Array.isArray(data?.data)) {
    const item = data.data[0];

    rate =
      item?.value ??
      item?.rate ??
      item?.metric_value;
  }

  rate = parsePositiveRate(rate);

  if (!rate) {
    throw new Error(
      "Africa API não retornou USD/MZN válido."
    );
  }

  return {
    rate,
    source: "Africa-API",
    updatedAt: new Date().toISOString(),
  };
}

// -----------------------------------------------------------------------------
// FALLBACK FX — AFRIRATE
// -----------------------------------------------------------------------------

async function getUsdMznFromAfriRate() {
  const url =
    "https://afrirate.com/api/v1/rates/latest?country=MZ";

  const data = await fetchJson(
    url,
    {
      method: "GET",
      headers: {
        Accept: "application/json",
      },
    },
    10000
  );

  let rate =
    data?.rate ??
    data?.data?.rate ??
    data?.data?.usdMzn ??
    data?.data?.USD?.MZN ??
    data?.rates?.MZN;

  rate = parsePositiveRate(rate);

  if (!rate) {
    throw new Error(
      "AfriRate não retornou USD/MZN válido."
    );
  }

  return {
    rate,
    source: "AfriRate",
    updatedAt:
      data?.updatedAt ||
      data?.timestamp ||
      new Date().toISOString(),
  };
}

// -----------------------------------------------------------------------------
// FALLBACK FX — MONEYCONVERT
// -----------------------------------------------------------------------------

async function getUsdMznFromMoneyConvert() {
  const url =
    "https://cdn.moneyconvert.net/api/latest.json";

  const data = await fetchJson(
    url,
    {
      method: "GET",
      headers: {
        Accept: "application/json",
      },
    },
    10000
  );

  let rate =
    data?.rates?.MZN ??
    data?.MZN ??
    data?.data?.rates?.MZN;

  rate = parsePositiveRate(rate);

  if (!rate) {
    throw new Error(
      "MoneyConvert não retornou USD/MZN válido."
    );
  }

  return {
    rate,
    source: "MoneyConvert",
    updatedAt:
      data?.date ||
      new Date().toISOString(),
  };
}

async function getUsdMzn(force = false) {
  const providers = [
    getUsdMznFromOpenERApi,
    getUsdMznFromAfricaApi,
    getUsdMznFromAfriRate,
    getUsdMznFromMoneyConvert,
  ];

  const errors = [];

  for (const provider of providers) {
    try {
      const result = await provider();

      if (
        result &&
        Number.isFinite(result.rate) &&
        result.rate > 0
      ) {
        return result;
      }
    } catch (error) {
      errors.push(
        `${provider.name}: ${error?.message || "erro"}`
      );
    }
  }

  throw new Error(
    `Todas as fontes USD/MZN falharam. ${errors.join(" | ")}`
  );
}

// -----------------------------------------------------------------------------
// USDT/USD
// -----------------------------------------------------------------------------

async function getUsdtUsdFromCoinbase() {
  const url =
    "https://api.coinbase.com/v2/exchange-rates?currency=USDT";

  const data = await fetchJson(
    url,
    {
      method: "GET",
      headers: {
        Accept: "application/json",
      },
    },
    10000
  );

  const rate = parsePositiveRate(
    data?.data?.rates?.USD
  );

  if (!rate) {
    throw new Error(
      "Coinbase não retornou USDT/USD válido."
    );
  }

  return {
    rate,
    source: "Coinbase",
    updatedAt: new Date().toISOString(),
  };
}

async function getUsdtUsdFromCoinGecko() {
  const url =
    "https://api.coingecko.com/api/v3/simple/price" +
    "?ids=tether&vs_currencies=usd";

  const data = await fetchJson(
    url,
    {
      method: "GET",
      headers: {
        Accept: "application/json",
      },
    },
    10000
  );

  const rate = parsePositiveRate(
    data?.tether?.usd
  );

  if (!rate) {
    throw new Error(
      "CoinGecko não retornou USDT/USD válido."
    );
  }

  return {
    rate,
    source: "CoinGecko",
    updatedAt: new Date().toISOString(),
  };
}

async function getUsdtUsd() {
  const providers = [
    getUsdtUsdFromCoinbase,
    getUsdtUsdFromCoinGecko,
  ];

  const errors = [];

  for (const provider of providers) {
    try {
      const result = await provider();

      if (
        result &&
        Number.isFinite(result.rate) &&
        result.rate > 0
      ) {
        return result;
      }
    } catch (error) {
      errors.push(
        `${provider.name}: ${error?.message || "erro"}`
      );
    }
  }

  // USDT é uma stablecoin indexada ao USD.
  // Só usamos 1.0 como último fallback da componente USDT/USD,
  // nunca como fallback do USD/MZN.
  return {
    rate: 1,
    source: "USDT-PEG",
    updatedAt: new Date().toISOString(),
    warning: errors.join(" | "),
  };
}

// -----------------------------------------------------------------------------
// REAL USDT/MZN RATE
// -----------------------------------------------------------------------------

async function getRealUsdtMznRate(force = false) {
  const now = Date.now();

  if (
    !force &&
    rateCache &&
    now - rateCache.timestamp < RATE_CACHE_MS
  ) {
    return rateCache.value;
  }

  const usdMzn = await getUsdMzn(force);
  const usdtUsd = await getUsdtUsd();

  const marketRate =
    Number(usdMzn.rate) *
    Number(usdtUsd.rate);

  if (
    !Number.isFinite(marketRate) ||
    marketRate <= 0
  ) {
    throw new Error(
      "Resultado USD/MZN × USDT/USD inválido."
    );
  }

  const spread = Number.isFinite(
    RATE_SPREAD_PERCENT
  )
    ? RATE_SPREAD_PERCENT
    : 0;

  const sellRate =
    marketRate *
    (1 + spread / 100);

  const result = {
    value: roundMoney(sellRate, 6),
    marketRate: roundMoney(marketRate, 6),
    usdMzn: roundMoney(usdMzn.rate, 6),
    usdtUsd: roundMoney(usdtUsd.rate, 8),
    spreadPercent: spread,
    source: `${usdMzn.source}+${usdtUsd.source}`,
    updatedAt: new Date().toISOString(),
    fxUpdatedAt: usdMzn.updatedAt,
  };

  rateCache = {
    timestamp: now,
    value: result,
  };

  return result;
}

// -----------------------------------------------------------------------------
// TRON
// -----------------------------------------------------------------------------

function topicToAddress(topic) {
  if (!topic) return null;

  const clean = String(topic).replace(/^0x/, "");

  if (clean.length !== 64) return null;

  try {
    return TronWeb.address.fromHex(
      "41" + clean.slice(-40)
    );
  } catch {
    return null;
  }
}

function topicToAmount(topic) {
  if (!topic) return null;

  try {
    const clean = String(topic).replace(/^0x/, "");

    if (!/^[0-9a-fA-F]{64}$/.test(clean)) {
      return null;
    }

    const raw = BigInt(`0x${clean}`);

    return Number(raw) / 10 ** USDT_DECIMALS;
  } catch {
    return null;
  }
}

async function getTransactionInfo(txHash) {
  const tronWeb = getTronWeb();

  const info = await tronWeb.trx.getTransactionInfo(
    txHash
  );

  if (!info || !info.id) {
    throw new Error(
      "Transação TRON não encontrada."
    );
  }

  return info;
}

async function verifyUsdtTransfer(txHash, expectedTo = null) {
  const hash = String(txHash || "").trim();

  if (!/^[a-fA-F0-9]{64}$/.test(hash)) {
    throw new Error("TX hash TRON inválido.");
  }

  const treasury =
    expectedTo || getTreasuryAddress();

  const info = await getTransactionInfo(hash);

  if (!info.receipt) {
    throw new Error(
      "Transação TRON ainda não possui receipt."
    );
  }

  if (
    info.receipt.result &&
    String(info.receipt.result).toUpperCase() !==
      "SUCCESS"
  ) {
    throw new Error(
      `Transação TRON não foi concluída com sucesso: ${info.receipt.result}`
    );
  }

  const url =
    `${TRON_HOST}/v1/transactions/${hash}/events` +
    "?only_confirmed=true";

  const response = await fetchJson(
    url,
    {
      method: "GET",
      headers: {
        Accept: "application/json",
        ...(process.env.TRON_PRO_API_KEY
          ? {
              "TRON-PRO-API-KEY":
                process.env.TRON_PRO_API_KEY,
            }
          : {}),
      },
    },
    15000
  );

  const events = Array.isArray(response?.data)
    ? response.data
    : [];

  const expectedContract =
    String(USDT_CONTRACT).toLowerCase();

  const expectedToNormalized =
    String(treasury).trim();

  let totalReceived = 0;
  let matched = false;

  for (const event of events) {
    const contract =
      event?.contract_address ||
      event?.contractAddress;

    const eventName =
      event?.event_name ||
      event?.eventName;

    if (
      String(contract || "").toLowerCase() !==
      expectedContract
    ) {
      continue;
    }

    if (eventName !== "Transfer") {
      continue;
    }

    const result = event?.result || {};

    const to =
      result?.to ||
      result?._to ||
      result?.["1"];

    const value =
      result?.value ||
      result?._value ||
      result?.["2"];

    let destination = null;

    if (typeof to === "string") {
      if (to.startsWith("T")) {
        destination = to;
      } else {
        destination = topicToAddress(to);
      }
    }

    if (
      !destination ||
      destination !== expectedToNormalized
    ) {
      continue;
    }

    let amount;

    if (
      typeof value === "string" &&
      /^\d+$/.test(value)
    ) {
      amount =
        Number(BigInt(value)) /
        10 ** USDT_DECIMALS;
    } else {
      amount = topicToAmount(value);
    }

    if (
      !Number.isFinite(amount) ||
      amount <= 0
    ) {
      continue;
    }

    totalReceived += amount;
    matched = true;
  }

  if (!matched || totalReceived <= 0) {
    throw new Error(
      "Nenhuma transferência USDT TRC20 confirmada para a tesouraria foi encontrada."
    );
  }

  return {
    confirmed: true,
    txHash: hash,
    treasuryAddress: expectedToNormalized,
    amount: roundMoney(totalReceived, 6),
    contract: USDT_CONTRACT,
    blockNumber: info.blockNumber || null,
  };
}

// -----------------------------------------------------------------------------
// WALLETS
// -----------------------------------------------------------------------------

async function getOrCreateWallet(asset) {
  const normalizedAsset =
    String(asset || "").trim().toUpperCase();

  if (!["MZN", "USDT"].includes(normalizedAsset)) {
    throw new Error("Asset de wallet inválido.");
  }

  const rows = await sql`
    SELECT *
    FROM wallets
    WHERE asset = ${normalizedAsset}
    ORDER BY id ASC
    LIMIT 1
  `;

  if (rows.length) {
    return rows[0];
  }

  if (normalizedAsset === "USDT") {
    const address = getTreasuryAddress();

    const inserted = await sql`
      INSERT INTO wallets
        (
          wallet_address,
          network,
          asset,
          balance,
          status,
          created_at,
          updated_at,
          user_id
        )
      VALUES
        (
          ${address},
          'TRON',
          'USDT',
          0,
          'ACTIVE',
          NOW(),
          NOW(),
          NULL
        )
      RETURNING *
    `;

    return inserted[0];
  }

  const inserted = await sql`
    INSERT INTO wallets
      (
        wallet_address,
        network,
        asset,
        balance,
        status,
        created_at,
        updated_at,
        user_id
      )
    VALUES
      (
        'USDTMZ-TREASURY',
        'MZN',
        'MZN',
        0,
        'ACTIVE',
        NOW(),
        NOW(),
        NULL
      )
    RETURNING *
  `;

  return inserted[0];
}

// -----------------------------------------------------------------------------
// MZN DEPOSITS
// -----------------------------------------------------------------------------

async function registerMZNDeposit(body) {
  const amount = positiveInteger(body.amount);

  if (!amount) {
    throw new Error(
      "Valor MZN deve ser um número inteiro positivo."
    );
  }

  if (amount < MIN_MZN || amount > MAX_MZN) {
    throw new Error(
      `Valor MZN deve estar entre ${MIN_MZN} e ${MAX_MZN}.`
    );
  }

  const source =
    normalizeSource(body.source);

  if (!isValidSource(source)) {
    throw new Error("Fonte de depósito inválida.");
  }

  const reference =
    String(body.reference || "").trim() ||
    makeReference("MZN");

  const existing = await sql`
    SELECT *
    FROM transactions
    WHERE reference = ${reference}
    LIMIT 1
  `;

  if (existing.length) {
    return {
      success: true,
      alreadyExists: true,
      transaction: existing[0],
    };
  }

  const rows = await sql`
    INSERT INTO transactions
      (
        user_id,
        type,
        asset,
        amount,
        status,
        reference,
        created_at
      )
    VALUES
      (
        'ADMIN',
        'DEPOSIT_MZN',
        'MZN',
        ${amount},
        'PENDING',
        ${reference},
        NOW()
      )
    RETURNING *
  `;

  return {
    success: true,
    transaction: rows[0],
  };
}

async function confirmMZNDeposit(body) {
  const reference =
    String(body.reference || "").trim();

  if (!reference) {
    throw new Error("reference é obrigatória.");
  }

  const result = await sql`
    WITH locked AS (
      SELECT *
      FROM transactions
      WHERE reference = ${reference}
        AND type = 'DEPOSIT_MZN'
      FOR UPDATE
    ),
    target AS (
      SELECT *
      FROM locked
      WHERE status = 'PENDING'
      LIMIT 1
    ),
    wallet AS (
      SELECT id
      FROM wallets
      WHERE asset = 'MZN'
      ORDER BY id ASC
      LIMIT 1
    ),
    updated_wallet AS (
      UPDATE wallets w
      SET
        balance =
          COALESCE(w.balance, 0) +
          (SELECT amount FROM target),
        updated_at = NOW()
      WHERE w.id = (SELECT id FROM wallet)
        AND EXISTS (SELECT 1 FROM target)
      RETURNING w.*
    ),
    updated_transaction AS (
      UPDATE transactions t
      SET
        status = 'COMPLETED'
      WHERE t.reference = ${reference}
        AND t.type = 'DEPOSIT_MZN'
        AND t.status = 'PENDING'
        AND EXISTS (SELECT 1 FROM updated_wallet)
      RETURNING t.*
    )
    SELECT
      (SELECT COUNT(*) FROM target) AS target_count,
      (SELECT COUNT(*) FROM updated_transaction) AS updated_count
  `;

  const row = result[0];

  if (
    Number(row?.updated_count || 0) > 0
  ) {
    return {
      success: true,
      confirmed: true,
      reference,
    };
  }

  const current = await sql`
    SELECT *
    FROM transactions
    WHERE reference = ${reference}
      AND type = 'DEPOSIT_MZN'
    LIMIT 1
  `;

  if (
    current.length &&
    current[0].status === "COMPLETED"
  ) {
    return {
      success: true,
      alreadyConfirmed: true,
      reference,
    };
  }

  throw new Error(
    "Depósito MZN não está pendente ou não foi possível confirmar."
  );
}

// -----------------------------------------------------------------------------
// USDT DEPOSITS
// -----------------------------------------------------------------------------

async function registerUSDTDeposit(body) {
  const txHash =
    String(
      body.tx_hash ||
        body.txHash ||
        body.reference ||
        ""
    ).trim();

  if (!txHash) {
    throw new Error("TX hash é obrigatório.");
  }

  if (!/^[a-fA-F0-9]{64}$/.test(txHash)) {
    throw new Error("TX hash TRON inválido.");
  }

  const source =
    normalizeSource(
      body.source || "USDT_TRON"
    );

  if (source !== "USDT_TRON") {
    throw new Error(
      "Depósito USDT deve usar a fonte USDT_TRON."
    );
  }

  const existing = await sql`
    SELECT *
    FROM transactions
    WHERE reference = ${txHash}
    LIMIT 1
  `;

  if (existing.length) {
    return {
      success: true,
      alreadyExists: true,
      transaction: existing[0],
    };
  }

  const rows = await sql`
    INSERT INTO transactions
      (
        user_id,
        type,
        asset,
        amount,
        status,
        reference,
        blockchain_tx_hash,
        created_at
      )
    VALUES
      (
        'ADMIN',
        'DEPOSIT_USDT',
        'USDT',
        0,
        'PENDING',
        ${txHash},
        ${txHash},
        NOW()
      )
    RETURNING *
  `;

  try {
    const verification =
      await verifyUsdtTransfer(
        txHash,
        getTreasuryAddress()
      );

    await confirmUSDTDeposit({
      reference: txHash,
      tx_hash: txHash,
    });

    return {
      success: true,
      confirmed: true,
      transaction: rows[0],
      blockchain: verification,
    };
  } catch (error) {
    return {
      success: true,
      confirmed: false,
      pending: true,
      transaction: rows[0],
      message:
        error?.message ||
        "Aguardando confirmação da blockchain.",
    };
  }
}

async function confirmUSDTDeposit(body) {
  const reference =
    String(
      body.reference ||
        body.tx_hash ||
        body.txHash ||
        ""
    ).trim();

  if (!reference) {
    throw new Error(
      "reference/TX hash é obrigatório."
    );
  }

  const txHash =
    String(
      body.tx_hash ||
        body.txHash ||
        reference
    ).trim();

  const verification =
    await verifyUsdtTransfer(
      txHash,
      getTreasuryAddress()
    );

  const amount =
    verification.amount;

  const result = await sql`
    WITH target AS (
      SELECT *
      FROM transactions
      WHERE reference = ${reference}
        AND type = 'DEPOSIT_USDT'
        AND status = 'PENDING'
      LIMIT 1
      FOR UPDATE
    ),
    wallet AS (
      SELECT id
      FROM wallets
      WHERE asset = 'USDT'
      ORDER BY id ASC
      LIMIT 1
    ),
    updated_wallet AS (
      UPDATE wallets w
      SET
        balance =
          COALESCE(w.balance, 0) +
          ${amount},
        updated_at = NOW()
      WHERE w.id = (SELECT id FROM wallet)
        AND EXISTS (SELECT 1 FROM target)
      RETURNING w.*
    ),
    updated_transaction AS (
      UPDATE transactions t
      SET
        amount = ${amount},
        status = 'COMPLETED',
        blockchain_tx_hash = ${txHash}
      WHERE t.reference = ${reference}
        AND t.type = 'DEPOSIT_USDT'
        AND t.status = 'PENDING'
        AND EXISTS (SELECT 1 FROM updated_wallet)
      RETURNING t.*
    )
    SELECT
      (SELECT COUNT(*) FROM updated_transaction)
        AS updated_count
  `;

  if (
    Number(result[0]?.updated_count || 0) > 0
  ) {
    return {
      success: true,
      confirmed: true,
      amount,
      txHash,
    };
  }

  const current = await sql`
    SELECT *
    FROM transactions
    WHERE reference = ${reference}
      AND type = 'DEPOSIT_USDT'
    LIMIT 1
  `;

  if (
    current.length &&
    current[0].status === "COMPLETED"
  ) {
    return {
      success: true,
      alreadyConfirmed: true,
      amount: Number(current[0].amount),
      txHash:
        current[0].blockchain_tx_hash ||
        txHash,
    };
  }

  throw new Error(
    "Depósito USDT não está pendente ou não foi possível confirmar."
  );
}

// -----------------------------------------------------------------------------
// CONVERSION MZN -> USDT
// -----------------------------------------------------------------------------

async function convertMZNToUSDT(body) {
  const amountMzn = positiveInteger(
    body.amount_mzn ??
      body.amount ??
      body.mzn
  );

  if (!amountMzn) {
    throw new Error(
      "amount_mzn deve ser um número inteiro positivo."
    );
  }

  if (
    amountMzn < MIN_MZN ||
    amountMzn > MAX_MZN
  ) {
    throw new Error(
      `Conversão deve estar entre ${MIN_MZN} e ${MAX_MZN} MZN.`
    );
  }

  const rate =
    await getRealUsdtMznRate(true);

  const usdtAmount =
    amountMzn / rate.value;

  const usdtRounded =
    roundMoney(usdtAmount, 6);

  if (usdtRounded <= 0) {
    throw new Error(
      "Quantidade USDT calculada inválida."
    );
  }

  const reference =
    String(body.reference || "").trim() ||
    makeReference("CONVERSION");

  const result = await sql`
    WITH mzn_wallet AS (
      SELECT id, COALESCE(balance, 0) AS balance
      FROM wallets
      WHERE asset = 'MZN'
      ORDER BY id ASC
      LIMIT 1
      FOR UPDATE
    ),
    usdt_wallet AS (
      SELECT id, COALESCE(balance, 0) AS balance
      FROM wallets
      WHERE asset = 'USDT'
      ORDER BY id ASC
      LIMIT 1
      FOR UPDATE
    ),
    checked AS (
      SELECT
        (SELECT balance FROM mzn_wallet) AS mzn_balance,
        (SELECT balance FROM usdt_wallet) AS usdt_balance
    ),
    debit_mzn AS (
      UPDATE wallets w
      SET
        balance =
          w.balance - ${amountMzn},
        updated_at = NOW()
      WHERE w.id = (SELECT id FROM mzn_wallet)
        AND (SELECT mzn_balance FROM checked) >= ${amountMzn}
      RETURNING w.*
    ),
    reserve_usdt AS (
      UPDATE wallets w
      SET
        balance =
          w.balance - ${usdtRounded},
        updated_at = NOW()
      WHERE w.id = (SELECT id FROM usdt_wallet)
        AND (SELECT usdt_balance FROM checked) >= ${usdtRounded}
        AND EXISTS (SELECT 1 FROM debit_mzn)
      RETURNING w.*
    )
    SELECT
      (SELECT COUNT(*) FROM debit_mzn)
        AS mzn_debited,
      (SELECT COUNT(*) FROM reserve_usdt)
        AS usdt_reserved
  `;

  const row = result[0];

  if (
    Number(row?.mzn_debited || 0) !== 1
  ) {
    throw new Error(
      "Saldo MZN insuficiente."
    );
  }

  if (
    Number(row?.usdt_reserved || 0) !== 1
  ) {
    throw new Error(
      "Liquidez USDT insuficiente."
    );
  }

  try {
    await sql`
      INSERT INTO transactions
        (
          user_id,
          type,
          asset,
          amount,
          status,
          reference,
          created_at
        )
      VALUES
        (
          'ADMIN',
          'CONVERSION',
          'MZN',
          ${amountMzn},
          'COMPLETED',
          ${reference},
          NOW()
        )
    `;

    await sql`
      INSERT INTO transactions
        (
          user_id,
          type,
          asset,
          amount,
          status,
          reference,
          created_at
        )
      VALUES
        (
          'ADMIN',
          'RESERVE_IN',
          'USDT',
          ${usdtRounded},
          'RESERVED',
          ${reference},
          NOW()
        )
    `;
  } catch (error) {
    // Tenta devolver os saldos se a criação do ledger falhar.
    await sql`
      UPDATE wallets
      SET
        balance = balance + ${amountMzn},
        updated_at = NOW()
      WHERE asset = 'MZN'
    `;

    await sql`
      UPDATE wallets
      SET
        balance = balance + ${usdtRounded},
        updated_at = NOW()
      WHERE asset = 'USDT'
    `;

    throw error;
  }

  return {
    success: true,
    reference,
    amountMzn,
    usdtAmount: usdtRounded,
    rate: rate.value,
    marketRate: rate.marketRate,
    source: rate.source,
    updatedAt: rate.updatedAt,
  };
}

// -----------------------------------------------------------------------------
// RELEASE RESERVATION
// -----------------------------------------------------------------------------

async function releaseReservation(body) {
  const reference =
    String(body.reference || "").trim();

  if (!reference) {
    throw new Error(
      "reference é obrigatória."
    );
  }

  const rows = await sql`
    SELECT *
    FROM transactions
    WHERE reference = ${reference}
      AND type = 'RESERVE_IN'
      AND asset = 'USDT'
    LIMIT 1
  `;

  if (!rows.length) {
    throw new Error(
      "Reserva USDT não encontrada."
    );
  }

  const transaction = rows[0];

  if (transaction.status === "COMPLETED") {
    return {
      success: true,
      alreadyReleased: true,
    };
  }

  if (transaction.status !== "RESERVED") {
    throw new Error(
      `Reserva não está em estado RESERVED: ${transaction.status}`
    );
  }

  const amount =
    Number(transaction.amount);

  await sql`
    WITH wallet AS (
      SELECT id
      FROM wallets
      WHERE asset = 'USDT'
      ORDER BY id ASC
      LIMIT 1
      FOR UPDATE
    ),
    updated_wallet AS (
      UPDATE wallets w
      SET
        balance =
          COALESCE(w.balance, 0) +
          ${amount},
        updated_at = NOW()
      WHERE w.id = (SELECT id FROM wallet)
      RETURNING w.id
    )
    UPDATE transactions
    SET status = 'COMPLETED'
    WHERE reference = ${reference}
      AND type = 'RESERVE_IN'
      AND status = 'RESERVED'
      AND EXISTS (SELECT 1 FROM updated_wallet)
  `;

  return {
    success: true,
    released: true,
    amount,
    reference,
  };
}

// -----------------------------------------------------------------------------
// PENDING DEPOSITS
// -----------------------------------------------------------------------------

async function getPendingDeposits() {
  const rows = await sql`
    SELECT *
    FROM transactions
    WHERE status = 'PENDING'
      AND type IN (
        'DEPOSIT_MZN',
        'DEPOSIT_USDT'
      )
    ORDER BY created_at DESC
    LIMIT 100
  `;

  return rows;
}

// -----------------------------------------------------------------------------
// LIQUIDITY SOURCES
// -----------------------------------------------------------------------------

async function getLiquiditySources() {
  const mznWallet =
    await getOrCreateWallet("MZN");

  const usdtWallet =
    await getOrCreateWallet("USDT");

  return {
    sources: SOURCES,
    pagar: {
      configured: pagarConfigured(),
      apiBaseUrl:
        PAGAR_API_BASE_URL,
      topups:
        pagarConfigured(),
    },
    treasury: {
      mznBalance:
        Number(mznWallet?.balance || 0),
      usdtBalance:
        Number(usdtWallet?.balance || 0),
    },
    tron: {
      configured:
        Boolean(
          process.env.TRON_PRO_API_KEY
        ),
      treasuryAddress:
        getTreasuryAddress(),
      contract:
        USDT_CONTRACT,
    },
  };
}

// -----------------------------------------------------------------------------
// DASHBOARD
// -----------------------------------------------------------------------------

async function getDashboard() {
  const mznWallet =
    await getOrCreateWallet("MZN");

  const usdtWallet =
    await getOrCreateWallet("USDT");

  let rate = null;
  let rateError = null;

  try {
    rate =
      await getRealUsdtMznRate(false);
  } catch (error) {
    rateError =
      error?.message ||
      "Erro no motor cambial.";
  }

  const pending =
    await getPendingDeposits();

  const transactions = await sql`
    SELECT *
    FROM transactions
    ORDER BY created_at DESC
    LIMIT 50
  `;

  const orders = await sql`
    SELECT *
    FROM orders
    ORDER BY created_at DESC
    LIMIT 50
  `;

  const withdrawals = await sql`
    SELECT *
    FROM withdrawals
    ORDER BY created_at DESC
    LIMIT 50
  `;

  const pagarTransactions =
    await sql`
      SELECT *
      FROM transactions
      WHERE reference ILIKE 'PAGAR-TOPUP-%'
      ORDER BY created_at DESC
      LIMIT 50
    `;

  const mznBalance =
    Number(mznWallet?.balance || 0);

  const usdtBalance =
    Number(usdtWallet?.balance || 0);

  let reservedUsdt = 0;

  const reservedRows = await sql`
    SELECT COALESCE(SUM(amount), 0) AS total
    FROM transactions
    WHERE asset = 'USDT'
      AND type = 'RESERVE
