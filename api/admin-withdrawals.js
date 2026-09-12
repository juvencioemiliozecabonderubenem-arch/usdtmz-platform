// api/admin-withdrawals.js
// USDTMZ — CENTRAL ADMIN
//
// IMPORTANTE:
// Esta API é EXCLUSIVAMENTE para o ADMIN.
// Nenhum cliente deve chamar esta API.
//
// Funções:
// - Dashboard da tesouraria
// - Taxa cambial real
// - Depósito MZN manual/bancário
// - Top-up M-Pesa/eMola via Pagar
// - Consulta de top-up Pagar
// - Depósito USDT TRC20
// - Verificação real da blockchain TRON
// - Conversão MZN -> USDT
// - Reserva USDT
// - Liberação de reserva
// - Fontes de liquidez
//
// NÃO cria API13.
// NÃO aceita operações de cliente.
// NÃO guarda secrets no frontend.

import {
  createHash,
  createHmac,
  timingSafeEqual,
  randomBytes
} from "node:crypto";

import { neon } from "@neondatabase/serverless";
import { TronWeb } from "tronweb";

const sql = neon(process.env.DATABASE_URL);

// ============================================================================
// CONFIGURAÇÃO
// ============================================================================

const COOKIE_NAME = "usdtmz_admin_session";

const MIN_MZN = 64;
const MAX_MZN = 40000;

const USDT_CONTRACT =
  process.env.USDT_TRON_CONTRACT ||
  "TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t";

const USDT_DECIMALS = 6;

const RATE_SPREAD_PERCENT = Number(
  process.env.USDTMZ_RATE_SPREAD_PERCENT || 0
);

const TRON_HOST = "https://api.trongrid.io";

const PAGAR_API_BASE_URL =
  process.env.PAGAR_API_BASE_URL ||
  "https://api.pagar.co.mz/api/v1";

const RATE_CACHE_MS = 60 * 1000;

let rateCache = null;

// ============================================================================
// FONTES PERMITIDAS
// ============================================================================

const SOURCES = [
  "MPESA_BUSINESS",
  "EMOLA_BUSINESS",
  "BANK",
  "USDT_TRON",
  "EXTERNAL_WALLET",
  "USDT_PURCHASE",
  "LIQUIDITY_PARTNER",
  "MANUAL_APPROVED"
];

// ============================================================================
// RESPOSTA JSON
// ============================================================================

function sendJson(res, status, body) {
  res.status(status);

  res.setHeader(
    "Content-Type",
    "application/json; charset=utf-8"
  );

  res.setHeader(
    "Cache-Control",
    "no-store"
  );

  return res.end(
    JSON.stringify(body)
  );
}

// ============================================================================
// AUTENTICAÇÃO ADMIN
// ============================================================================

function safeCompare(a, b) {
  if (
    typeof a !== "string" ||
    typeof b !== "string"
  ) {
    return false;
  }

  const aa = Buffer.from(a);
  const bb = Buffer.from(b);

  if (aa.length !== bb.length) {
    return false;
  }

  return timingSafeEqual(aa, bb);
}

function parseCookies(req) {
  const header =
    req.headers?.cookie || "";

  const cookies = {};

  for (
    const part of header.split(";")
  ) {
    const index =
      part.indexOf("=");

    if (index === -1) {
      continue;
    }

    const key =
      part.slice(0, index).trim();

    const value =
      part.slice(index + 1).trim();

    cookies[key] =
      decodeURIComponent(value);
  }

  return cookies;
}

function verifyAdminSession(req) {
  const cookies =
    parseCookies(req);

  const token =
    cookies[COOKIE_NAME];

  if (!token) {
    return null;
  }

  const secret =
    process.env.ADMIN_SESSION_SECRET;

  if (!secret) {
    return null;
  }

  const parts =
    token.split(".");

  if (parts.length !== 2) {
    return null;
  }

  const [
    payloadEncoded,
    signature
  ] = parts;

  const expected =
    createHmac(
      "sha256",
      secret
    )
      .update(payloadEncoded)
      .digest("base64url");

  if (
    !safeCompare(
      signature,
      expected
    )
  ) {
    return null;
  }

  let payload;

  try {
    payload = JSON.parse(
      Buffer
        .from(
          payloadEncoded,
          "base64url"
        )
        .toString("utf8")
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

  if (!payload.email) {
    return null;
  }

  if (
    !Number.isFinite(
      Number(payload.exp)
    )
  ) {
    return null;
  }

  if (
    Number(payload.exp) <=
    Date.now()
  ) {
    return null;
  }

  return payload;
}

function requireAdmin(req) {
  const admin =
    verifyAdminSession(req);

  if (!admin) {
    const error =
      new Error(
        "Acesso permitido somente ao administrador."
      );

    error.statusCode = 401;

    throw error;
  }

  return admin;
}

// ============================================================================
// UTILITÁRIOS
// ============================================================================

function makeReference(
  prefix = "TREASURY"
) {
  return (
    `${prefix}-${Date.now()}-` +
    randomBytes(8)
      .toString("hex")
      .toUpperCase()
  );
}

function normalizeSource(value) {
  return String(value || "")
    .trim()
    .toUpperCase();
}

function isValidSource(value) {
  return SOURCES.includes(
    normalizeSource(value)
  );
}

function positiveNumber(value) {
  const number =
    Number(value);

  if (
    !Number.isFinite(number) ||
    number <= 0
  ) {
    return null;
  }

  return number;
}

function positiveInteger(value) {
  const number =
    Number(value);

  if (
    !Number.isInteger(number) ||
    number <= 0
  ) {
    return null;
  }

  return number;
}

function roundMoney(
  value,
  decimals = 6
) {
  const number =
    Number(value);

  if (
    !Number.isFinite(number)
  ) {
    return 0;
  }

  const factor =
    10 ** decimals;

  return (
    Math.round(
      number * factor
    ) / factor
  );
}

function validTronAddress(
  address
) {
  if (!address) {
    return false;
  }

  try {
    return TronWeb.isAddress(
      String(address).trim()
    );
  } catch {
    return false;
  }
}

function getTreasuryAddress() {
  const address =
    String(
      process.env.TREASURY_TRON_ADDRESS ||
      process.env.USDTMZ_TRON_WALLET_ADDRESS ||
      process.env.TRON_TREASURY_ADDRESS ||
      ""
    ).trim();

  if (
    !validTronAddress(address)
  ) {
    throw new Error(
      "Endereço TRON da tesouraria não configurado ou inválido."
    );
  }

  return address;
}

function getTronWeb() {
  const apiKey =
    process.env.TRON_PRO_API_KEY;

  const options = {
    fullHost: TRON_HOST
  };

  if (apiKey) {
    options.headers = {
      "TRON-PRO-API-KEY":
        apiKey
    };
  }

  return new TronWeb(options);
}

async function fetchJson(
  url,
  options = {},
  timeoutMs = 10000
) {
  const controller =
    new AbortController();

  const timeout =
    setTimeout(
      () => controller.abort(),
      timeoutMs
    );

  try {
    const response =
      await fetch(
        url,
        {
          ...options,
          signal:
            controller.signal
        }
      );

    const text =
      await response.text();

    let data;

    try {
      data =
        text
          ? JSON.parse(text)
          : {};
    } catch {
      data = {
        raw: text
      };
    }

    if (!response.ok) {
      const error =
        new Error(
          data?.message ||
          data?.error ||
          `HTTP ${response.status}`
        );

      error.status =
        response.status;

      error.data = data;

      throw error;
    }

    return data;
  } finally {
    clearTimeout(timeout);
  }
}

// ============================================================================
// PAGAR — SOMENTE TESOURARIA ADMIN
// ============================================================================

function pagarConfigured() {
  return Boolean(
    process.env.PAGAR_API_KEY &&
    process.env.PAGAR_SIGNING_SECRET
  );
}

async function pagarGet(
  path
) {
  if (!pagarConfigured()) {
    throw new Error(
      "Pagar não configurado."
    );
  }

  const url =
    `${PAGAR_API_BASE_URL}${path}`;

  return fetchJson(
    url,
    {
      method: "GET",
      headers: {
        Authorization:
          `Bearer ${process.env.PAGAR_API_KEY}`,
        Accept:
          "application/json"
      }
    },
    15000
  );
}

async function pagarPost(
  path,
  body,
  idempotencyKey
) {
  const apiKey =
    process.env.PAGAR_API_KEY;

  const signingSecret =
    process.env.PAGAR_SIGNING_SECRET;

  if (
    !apiKey ||
    !signingSecret
  ) {
    throw new Error(
      "PAGAR_API_KEY ou PAGAR_SIGNING_SECRET não configurado."
    );
  }

  const timestamp =
    Date.now().toString();

  const nonce =
    randomBytes(18)
      .toString("base64url");

  const rawBody =
    JSON.stringify(body);

  const bodyHash =
    createHash("sha256")
      .update(rawBody)
      .digest("hex");

  const url =
    `${PAGAR_API_BASE_URL}${path}`;

  const canonicalPath =
    new URL(url).pathname;

  const canonical = [
    timestamp,
    nonce,
    "POST",
    canonicalPath,
    bodyHash
  ].join("\n");

  const signature =
    createHmac(
      "sha256",
      signingSecret
    )
      .update(canonical)
      .digest("hex");

  return fetchJson(
    url,
    {
      method: "POST",

      headers: {
        Authorization:
          `Bearer ${apiKey}`,

        "Content-Type":
          "application/json",

        Accept:
          "application/json",

        "Idempotency-Key":
          idempotencyKey,

        "X-Pagar-Timestamp":
          timestamp,

        "X-Pagar-Nonce":
          nonce,

        "X-Pagar-Signature":
          `v1=${signature}`
      },

      body: rawBody
    },
    20000
  );
}

// ============================================================================
// PAGAR — CRIAR TOP-UP DA TESOURARIA
// ============================================================================

async function createPagarTreasuryTopup(
  body
) {
  if (!pagarConfigured()) {
    throw new Error(
      "Pagar não configurado. Configure PAGAR_API_KEY e PAGAR_SIGNING_SECRET."
    );
  }

  const amount =
    positiveInteger(
      body.amount_mzn
    );

  if (!amount) {
    throw new Error(
      "amount_mzn deve ser um número inteiro."
    );
  }

  if (
    amount < 20 ||
    amount > MAX_MZN
  ) {
    throw new Error(
      "O top-up deve estar entre 20 e 40000 MZN."
    );
  }

  const method =
    String(
      body.method || ""
    )
      .trim()
      .toUpperCase();

  if (
    method !== "MPESA" &&
    method !== "EMOLA"
  ) {
    throw new Error(
      "Método inválido. Use MPESA ou EMOLA."
    );
  }

  const paymentPhone =
    String(
      body.payment_phone ||
      body.phone ||
      ""
    ).replace(
      /\D/g,
      ""
    );

  if (
    !/^[0-9]{9}$/.test(
      paymentPhone
    )
  ) {
    throw new Error(
      "Número deve conter exatamente 9 dígitos."
    );
  }

  const reference =
    String(
      body.reference || ""
    ).trim() ||
    makeReference(
      "PAGAR-TOPUP"
    );

  if (
    !/^[A-Za-z0-9._:-]{3,100}$/.test(
      reference
    )
  ) {
    throw new Error(
      "Reference inválida."
    );
  }

  // --------------------------------------------------------------------------
  // VERIFICAR SE JÁ EXISTE
  // --------------------------------------------------------------------------

  const existing =
    await sql`
      SELECT
        id,
        type,
        asset,
        amount,
        status,
        reference,
        created_at
      FROM transactions
      WHERE reference = ${reference}
      ORDER BY id DESC
      LIMIT 1
    `;

  if (existing.length) {
    const transaction =
      existing[0];

    if (
      transaction.status ===
      "COMPLETED"
    ) {
      return {
        success: true,
        alreadyCompleted: true,
        reference,
        transaction
      };
    }

    if (
      transaction.status ===
      "PENDING"
    ) {
      return {
        success: true,
        alreadyPending: true,
        reference,
        transaction
      };
    }

    if (
      transaction.status ===
      "FAILED"
    ) {
      throw new Error(
        "Esta referência já foi utilizada numa operação FAILED."
      );
    }
  }

  // --------------------------------------------------------------------------
  // CRIAR LEDGER LOCAL
  // --------------------------------------------------------------------------

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
      ${amount},
      'PENDING',
      ${reference},
      NOW()
    )
  `;

  // --------------------------------------------------------------------------
  // CHAMAR PAGAR
  // --------------------------------------------------------------------------

  let pagarResponse;

  try {
    pagarResponse =
      await pagarPost(
        "/wallet/topups",
        {
          reference,
          amountMzn:
            amount,
          method,
          paymentPhone
        },
        `topup:${reference}`
      );
  } catch (error) {
    await sql`
      UPDATE transactions
      SET status = 'FAILED'
      WHERE reference = ${reference}
        AND type = 'DEPOSIT_MZN'
        AND status = 'PENDING'
    `;

    throw error;
  }

  const topup =
    pagarResponse?.topup ||
    pagarResponse?.data?.topup ||
    pagarResponse?.data ||
    null;

  const status =
    String(
      topup?.status ||
      pagarResponse?.status ||
      ""
    ).toUpperCase();

  // --------------------------------------------------------------------------
  // SOMENTE PAID CREDITA
  // --------------------------------------------------------------------------

  if (status === "PAID") {
    const confirmation =
      await confirmMZNDeposit({
        reference
      });

    return {
      success: true,
      status: "PAID",
      confirmed: true,
      reference,
      pagar:
        pagarResponse,
      confirmation
    };
  }

  // --------------------------------------------------------------------------
  // FAILED / CANCELLED
  // --------------------------------------------------------------------------

  if (
    status === "FAILED" ||
    status === "CANCELLED"
  ) {
    await sql`
      UPDATE transactions
      SET status = 'FAILED'
      WHERE reference = ${reference}
        AND type = 'DEPOSIT_MZN'
        AND status = 'PENDING'
    `;

    return {
      success: true,
      status,
      confirmed: false,
      reference,
      pagar:
        pagarResponse
    };
  }

  // --------------------------------------------------------------------------
  // PENDING / PROCESSING
  // --------------------------------------------------------------------------

  return {
    success: true,
    status:
      status ||
      "PROCESSING",
    confirmed: false,
    reference,
    pagar:
      pagarResponse,

    message:
      "Top-up ainda não está PAID. O saldo MZN não foi creditado."
  };
}

// ============================================================================
// PAGAR — CONSULTAR TOP-UP
// ============================================================================

async function checkPagarTreasuryTopup(
  body
) {
  const reference =
    String(
      body.reference || ""
    ).trim();

  if (!reference) {
    throw new Error(
      "reference é obrigatória."
    );
  }

  const pagarResponse =
    await pagarGet(
      `/wallet/topups/by-reference/${encodeURIComponent(reference)}`
    );

  const topup =
    pagarResponse?.topup ||
    pagarResponse?.data?.topup ||
    pagarResponse?.data ||
    null;

  const status =
    String(
      topup?.status ||
      pagarResponse?.status ||
      ""
    ).toUpperCase();

  if (status === "PAID") {
    const confirmation =
      await confirmMZNDeposit({
        reference
      });

    return {
      success: true,
      status: "PAID",
      confirmed: true,
      reference,
      pagar:
        pagarResponse,
      confirmation
    };
  }

  if (
    status === "FAILED" ||
    status === "CANCELLED"
  ) {
    await sql`
      UPDATE transactions
      SET status = 'FAILED'
      WHERE reference = ${reference}
        AND type = 'DEPOSIT_MZN'
        AND status = 'PENDING'
    `;

    return {
      success: true,
      status,
      confirmed: false,
      reference,
      pagar:
        pagarResponse
    };
  }

  return {
    success: true,
    status:
      status ||
      "PROCESSING",
    confirmed: false,
    reference,
    pagar:
      pagarResponse
  };
}

// ============================================================================
// MOTOR CAMBIAL
// ============================================================================

function parsePositiveRate(
  value
) {
  const rate =
    Number(value);

  if (
    !Number.isFinite(rate) ||
    rate <= 0
  ) {
    return null;
  }

  return rate;
}

// -----------------------------------------------------------------------------
// USD/MZN — OPEN ER API
// -----------------------------------------------------------------------------

async function getUsdMznFromOpenERApi() {
  const data =
    await fetchJson(
      "https://open.er-api.com/v6/latest/USD",
      {
        method: "GET",
        headers: {
          Accept:
            "application/json"
        }
      },
      10000
    );

  if (
    data?.result !==
    "success"
  ) {
    throw new Error(
      "Open ER-API retornou erro."
    );
  }

  const rate =
    parsePositiveRate(
      data?.rates?.MZN
    );

  if (!rate) {
    throw new Error(
      "Open ER-API não retornou USD/MZN."
    );
  }

  return {
    rate,
    source:
      "OpenER-API",
    updatedAt:
      data?.time_last_update_utc ||
      new Date().toISOString()
  };
}

// -----------------------------------------------------------------------------
// USD/MZN — AFRICA API
// -----------------------------------------------------------------------------

async function getUsdMznFromAfricaApi() {
  const apiKey =
    process.env.AFRICA_API_KEY;

  if (!apiKey) {
    throw new Error(
      "AFRICA_API_KEY não configurada."
    );
  }

  const url =
    "https://api.africa-api.com/v1/data" +
    "?country_code=MZ" +
    "&metric_key=official_exchange_rate_latest_lcu_per_usd" +
    "&latest=true";

  const data =
    await fetchJson(
      url,
      {
        method: "GET",
        headers: {
          Accept:
            "application/json",

          Authorization:
            `Bearer ${apiKey}`,

          "X-API-Key":
            apiKey
        }
      },
      10000
    );

  let rate =
    data?.data?.value ??
    data?.data?.rate ??
    data?.value ??
    data?.rate;

  if (
    Array.isArray(
      data?.data
    )
  ) {
    const item =
      data.data[0];

    rate =
      item?.value ??
      item?.rate ??
      item?.metric_value;
  }

  rate =
    parsePositiveRate(
      rate
    );

  if (!rate) {
    throw new Error(
      "Africa API não retornou USD/MZN válido."
    );
  }

  return {
    rate,
    source:
      "Africa-API",
    updatedAt:
      new Date().toISOString()
  };
}

// -----------------------------------------------------------------------------
// USD/MZN — AFRIRATE
// -----------------------------------------------------------------------------

async function getUsdMznFromAfriRate() {
  const data =
    await fetchJson(
      "https://afrirate.com/api/v1/rates/latest?country=MZ",
      {
        method: "GET",
        headers: {
          Accept:
            "application/json"
        }
      },
      10000
    );

  let rate =
    data?.rate ??
    data?.data?.rate ??
    data?.data?.usdMzn ??
    data?.data?.USD?.MZN ??
    data?.rates?.MZN;

  rate =
    parsePositiveRate(
      rate
    );

  if (!rate) {
    throw new Error(
      "AfriRate não retornou USD/MZN válido."
    );
  }

  return {
    rate,
    source:
      "AfriRate",
    updatedAt:
      data?.updatedAt ||
      data?.timestamp ||
      new Date().toISOString()
  };
}

// -----------------------------------------------------------------------------
// USD/MZN — MONEYCONVERT
// -----------------------------------------------------------------------------

async function getUsdMznFromMoneyConvert() {
  const data =
    await fetchJson(
      "https://cdn.moneyconvert.net/api/latest.json",
      {
        method: "GET",
        headers: {
          Accept:
            "application/json"
        }
      },
      10000
    );

  let rate =
    data?.rates?.MZN ??
    data?.MZN ??
    data?.data?.rates?.MZN;

  rate =
    parsePositiveRate(
      rate
    );

  if (!rate) {
    throw new Error(
      "MoneyConvert não retornou USD/MZN válido."
    );
  }

  return {
    rate,
    source:
      "MoneyConvert",
    updatedAt:
      data?.date ||
      new Date().toISOString()
  };
}

async function getUsdMzn() {
  const providers = [
    getUsdMznFromOpenERApi,
    getUsdMznFromAfricaApi,
    getUsdMznFromAfriRate,
    getUsdMznFromMoneyConvert
  ];

  const errors = [];

  for (
    const provider of providers
  ) {
    try {
      const result =
        await provider();

      if (
        result &&
        Number.isFinite(
          result.rate
        ) &&
        result.rate > 0
      ) {
        return result;
      }
    } catch (error) {
      errors.push(
        `${provider.name}: ${
          error?.message ||
          "erro"
        }`
      );
    }
  }

  throw new Error(
    "Todas as fontes USD/MZN falharam: " +
    errors.join(" | ")
  );
}

// -----------------------------------------------------------------------------
// USDT/USD — COINBASE
// -----------------------------------------------------------------------------

async function getUsdtUsdFromCoinbase() {
  const data =
    await fetchJson(
      "https://api.coinbase.com/v2/exchange-rates?currency=USDT",
      {
        method: "GET",
        headers: {
          Accept:
            "application/json"
        }
      },
      10000
    );

  const rate =
    parsePositiveRate(
      data?.data?.rates?.USD
    );

  if (!rate) {
    throw new Error(
      "Coinbase não retornou USDT/USD válido."
    );
  }

  return {
    rate,
    source:
      "Coinbase",
    updatedAt:
      new Date().toISOString()
  };
}

// -----------------------------------------------------------------------------
// USDT/USD — COINGECKO
// -----------------------------------------------------------------------------

async function getUsdtUsdFromCoinGecko() {
  const data =
    await fetchJson(
      "https://api.coingecko.com/api/v3/simple/price?ids=tether&vs_currencies=usd",
      {
        method: "GET",
        headers: {
          Accept:
            "application/json"
        }
      },
      10000
    );

  const rate =
    parsePositiveRate(
      data?.tether?.usd
    );

  if (!rate) {
    throw new Error(
      "CoinGecko não retornou USDT/USD válido."
    );
  }

  return {
    rate,
    source:
      "CoinGecko",
    updatedAt:
      new Date().toISOString()
  };
}

async function getUsdtUsd() {
  const providers = [
    getUsdtUsdFromCoinbase,
    getUsdtUsdFromCoinGecko
  ];

  const errors = [];

  for (
    const provider of providers
  ) {
    try {
      const result =
        await provider();

      if (
        result &&
        Number.isFinite(
          result.rate
        ) &&
        result.rate > 0
      ) {
        return result;
      }
    } catch (error) {
      errors.push(
        `${provider.name}: ${
          error?.message ||
          "erro"
        }`
      );
    }
  }

  // USDT/USD somente.
  // Não substitui USD/MZN.
  return {
    rate: 1,
    source:
      "USDT-PEG",
    updatedAt:
      new Date().toISOString(),
    warning:
      errors.join(" | ")
  };
}

// -----------------------------------------------------------------------------
// TAXA FINAL
// -----------------------------------------------------------------------------

async function getRealUsdtMznRate(
  force = false
) {
  const now =
    Date.now();

  if (
    !force &&
    rateCache &&
    now -
      rateCache.timestamp <
      RATE_CACHE_MS
  ) {
    return rateCache.value;
  }

  const usdMzn =
    await getUsdMzn();

  const usdtUsd =
    await getUsdtUsd();

  const marketRate =
    Number(usdMzn.rate) *
    Number(usdtUsd.rate);

  if (
    !Number.isFinite(
      marketRate
    ) ||
    marketRate <= 0
  ) {
    throw new Error(
      "Resultado USD/MZN × USDT/USD inválido."
    );
  }

  const spread =
    Number.isFinite(
      RATE_SPREAD_PERCENT
    )
      ? RATE_SPREAD_PERCENT
      : 0;

  const sellRate =
    marketRate *
    (1 + spread / 100);

  const result = {
    value:
      roundMoney(
        sellRate,
        6
      ),

    marketRate:
      roundMoney(
        marketRate,
        6
      ),

    usdMzn:
      roundMoney(
        usdMzn.rate,
        6
      ),

    usdtUsd:
      roundMoney(
        usdtUsd.rate,
        8
      ),

    spreadPercent:
      spread,

    source:
      `${usdMzn.source}+${usdtUsd.source}`,

    updatedAt:
      new Date().toISOString(),

    fxUpdatedAt:
      usdMzn.updatedAt
  };

  rateCache = {
    timestamp: now,
    value: result
  };

  return result;
}

// ============================================================================
// TRON
// ============================================================================

function topicToAddress(
  topic
) {
  if (!topic) {
    return null;
  }

  const clean =
    String(topic)
      .replace(/^0x/, "");

  if (
    clean.length !== 64
  ) {
    return null;
  }

  try {
    return TronWeb.address.fromHex(
      "41" +
      clean.slice(-40)
    );
  } catch {
    return null;
  }
}

function topicToAmount(
  topic
) {
  if (!topic) {
    return null;
  }

  try {
    const clean =
      String(topic)
        .replace(/^0x/, "");

    if (
      !/^[0-9a-fA-F]{64}$/.test(
        clean
      )
    ) {
      return null;
    }

    const raw =
      BigInt(
        `0x${clean}`
      );

    return (
      Number(raw) /
      10 ** USDT_DECIMALS
    );
  } catch {
    return null;
  }
}

async function getTransactionInfo(
  txHash
) {
  const tronWeb =
    getTronWeb();

  const info =
    await tronWeb.trx.getTransactionInfo(
      txHash
    );

  if (
    !info ||
    !info.id
  ) {
    throw new Error(
      "Transação TRON não encontrada."
    );
  }

  return info;
}

// -----------------------------------------------------------------------------
// VERIFICAR USDT RECEBIDO
// -----------------------------------------------------------------------------

async function verifyUsdtTransfer(
  txHash,
  expectedTo = null
) {
  const hash =
    String(
      txHash || ""
    ).trim();

  if (
    !/^[a-fA-F0-9]{64}$/.test(
      hash
    )
  ) {
    throw new Error(
      "TX hash TRON inválido."
    );
  }

  const treasury =
    expectedTo ||
    getTreasuryAddress();

  const info =
    await getTransactionInfo(
      hash
    );

  if (!info.receipt) {
    throw new Error(
      "Transação TRON ainda não possui receipt."
    );
  }

  if (
    info.receipt.result &&
    String(
      info.receipt.result
    ).toUpperCase() !==
      "SUCCESS"
  ) {
    throw new Error(
      `Transação TRON falhou: ${info.receipt.result}`
    );
  }

  const url =
    `${TRON_HOST}/v1/transactions/${hash}/events` +
    "?only_confirmed=true";

  const response =
    await fetchJson(
      url,
      {
        method: "GET",
        headers: {
          Accept:
            "application/json",

          ...(process.env
            .TRON_PRO_API_KEY
            ? {
                "TRON-PRO-API-KEY":
                  process.env
                    .TRON_PRO_API_KEY
              }
            : {})
        }
      },
      15000
    );

  const events =
    Array.isArray(
      response?.data
    )
      ? response.data
      : [];

  const expectedContract =
    String(
      USDT_CONTRACT
    ).toLowerCase();

  let totalReceived = 0;

  let matched = false;

  for (
    const event of events
  ) {
    const contract =
      event?.contract_address ||
      event?.contractAddress;

    const eventName =
      event?.event_name ||
      event?.eventName;

    if (
      String(
        contract || ""
      ).toLowerCase() !==
      expectedContract
    ) {
      continue;
    }

    if (
      eventName !==
      "Transfer"
    ) {
      continue;
    }

    const result =
      event?.result || {};

    const to =
      result?.to ||
      result?._to ||
      result?.["1"];

    const value =
      result?.value ||
      result?._value ||
      result?.["2"];

    let destination =
      null;

    if (
      typeof to ===
      "string"
    ) {
      if (
        to.startsWith("T")
      ) {
        destination = to;
      } else {
        destination =
          topicToAddress(
            to
          );
      }
    }

    if (
      destination !==
      treasury
    ) {
      continue;
    }

    let amount;

    if (
      typeof value ===
        "string" &&
      /^\d+$/.test(
        value
      )
    ) {
      amount =
        Number(
          BigInt(value)
        ) /
        10 **
          USDT_DECIMALS;
    } else {
      amount =
        topicToAmount(
          value
        );
    }

    if (
      !Number.isFinite(
        amount
      ) ||
      amount <= 0
    ) {
      continue;
    }

    totalReceived +=
      amount;

    matched = true;
  }

  if (
    !matched ||
    totalReceived <= 0
  ) {
    throw new Error(
      "Nenhuma transferência USDT TRC20 confirmada para a tesouraria foi encontrada."
    );
  }

  return {
    confirmed: true,

    txHash: hash,

    treasuryAddress:
      treasury,

    amount:
      roundMoney(
        totalReceived,
        6
      ),

    contract:
      USDT_CONTRACT,

    blockNumber:
      info.blockNumber ||
      null
  };
}

// ============================================================================
// WALLETS DA TESOURARIA
// ============================================================================

async function getOrCreateWallet(
  asset
) {
  const normalized =
    String(asset || "")
      .trim()
      .toUpperCase();

  if (
    normalized !== "MZN" &&
    normalized !== "USDT"
  ) {
    throw new Error(
      "Asset inválido."
    );
  }

  const rows =
    await sql`
      SELECT *
      FROM wallets
