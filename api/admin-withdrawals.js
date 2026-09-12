// api/admin-withdrawals.js
// USDTMZ — CENTRAL ADMIN
//
// API06 — TESOURARIA CENTRAL
//
// EXCLUSIVAMENTE ADMIN.
// NÃO é API de cliente.
// NÃO cria API13.
//
// FUNÇÕES:
// - Dashboard da tesouraria
// - Motor cambial real USD/MZN + USDT/USD
// - M-Pesa/e-Mola via Pagar
// - Consulta de top-up Pagar
// - Depósito MZN manual/bancário
// - Depósito USDT TRC20
// - Verificação real na blockchain TRON
// - Conversão MZN -> USDT
// - Reserva USDT
// - Liberação de reserva
// - Fontes de liquidez
// - Registro de funding
// - Operações recentes
// - Depósitos pendentes
//
// SECRETS SOMENTE NO VERCEL.
// NUNCA enviar AFRICA_API_KEY, Pagar secrets ou private key ao frontend.

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

const USDT_DECIMALS = 6;

const USDT_CONTRACT =
  process.env.USDT_TRON_CONTRACT ||
  "TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t";

const TRON_HOST =
  process.env.TRON_HOST ||
  "https://api.trongrid.io";

const PAGAR_API_BASE_URL =
  process.env.PAGAR_API_BASE_URL ||
  "https://api.pagar.co.mz/api/v1";

const RATE_CACHE_MS = 60 * 1000;

const RATE_SPREAD_PERCENT = Number(
  process.env.USDTMZ_RATE_SPREAD_PERCENT || 0
);

let rateCache = null;

// ============================================================================
// FONTES DE LIQUIDEZ
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
// RESPOSTA
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
// AUTH ADMIN
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

    try {
      cookies[key] =
        decodeURIComponent(value);
    } catch {
      cookies[key] = value;
    }
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

function positiveNumber(value) {
  const n = Number(value);

  if (
    !Number.isFinite(n) ||
    n <= 0
  ) {
    return null;
  }

  return n;
}

function positiveInteger(value) {
  const n = Number(value);

  if (
    !Number.isInteger(n) ||
    n <= 0
  ) {
    return null;
  }

  return n;
}

function roundMoney(
  value,
  decimals = 6
) {
  const n = Number(value);

  if (!Number.isFinite(n)) {
    return 0;
  }

  const factor =
    10 ** decimals;

  return (
    Math.round(
      n * factor
    ) / factor
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

function validTronAddress(address) {
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
  const options = {
    fullHost: TRON_HOST
  };

  if (
    process.env.TRON_PRO_API_KEY
  ) {
    options.headers = {
      "TRON-PRO-API-KEY":
        process.env.TRON_PRO_API_KEY
    };
  }

  return new TronWeb(options);
}

async function fetchJson(
  url,
  options = {},
  timeoutMs = 15000
) {
  const controller =
    new AbortController();

  const timer =
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

    let data = {};

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
    clearTimeout(timer);
  }
}

async function readBody(req) {
  if (
    req.body &&
    typeof req.body === "object"
  ) {
    return req.body;
  }

  let raw = "";

  for await (const chunk of req) {
    raw += chunk.toString();
  }

  if (!raw) {
    return {};
  }

  try {
    return JSON.parse(raw);
  } catch {
    throw new Error(
      "JSON inválido."
    );
  }
}

// ============================================================================
// PAGAR
// ============================================================================

function pagarConfigured() {
  return Boolean(
    process.env.PAGAR_API_KEY &&
    process.env.PAGAR_SIGNING_SECRET
  );
}

async function pagarGet(path) {
  if (!pagarConfigured()) {
    throw new Error(
      "Pagar não configurado."
    );
  }

  return fetchJson(
    `${PAGAR_API_BASE_URL}${path}`,
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

  // CORRETO: SHA256 do corpo.
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
// PAGAR — TOP-UP TESOURARIA
// ============================================================================

async function createPagarTreasuryTopup(
  body
) {
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

  const phone =
    String(
      body.payment_phone ||
      body.phone ||
      ""
    ).replace(/\D/g, "");

  if (
    !/^[0-9]{9}$/.test(phone)
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
    const tx =
      existing[0];

    if (
      tx.status === "COMPLETED"
    ) {
      return {
        success: true,
        alreadyCompleted: true,
        reference,
        transaction: tx
      };
    }

    if (
      tx.status === "PENDING"
    ) {
      return {
        success: true,
        alreadyPending: true,
        reference,
        transaction: tx
      };
    }

    if (
      tx.status === "FAILED"
    ) {
      throw new Error(
        "Esta referência já foi utilizada numa operação FAILED."
      );
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
      NULL,
      'DEPOSIT_MZN',
      'MZN',
      ${amount},
      'PENDING',
      ${reference},
      NOW()
    )
  `;

  let pagarResponse;

  try {
    pagarResponse =
      await pagarPost(
        "/wallet/topups",
        {
          reference,
          amountMzn: amount,
          method,
          paymentPhone: phone
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

  if (status === "PAID") {
    return confirmMZNDeposit({
      reference
    });
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
      status || "PROCESSING",
    confirmed: false,
    reference,
    pagar:
      pagarResponse,
    message:
      "Top-up ainda não está PAID. O Fundo MZN não foi creditado."
  };
}

// ============================================================================
// PAGAR — CONSULTAR
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
    return confirmMZNDeposit({
      reference
    });
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
      status || "PROCESSING",
    confirmed: false,
    reference,
    pagar:
      pagarResponse
  };
}

// ============================================================================
// MOTOR CAMBIAL REAL
// ============================================================================

function parsePositiveRate(value) {
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

// ============================================================================
// AFRICA API — USD/MZN
// ============================================================================

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
    parsePositiveRate(rate);

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

// ============================================================================
// OPEN ER API — FALLBACK USD/MZN
// ============================================================================

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

// ============================================================================
// MONEYCONVERT — FALLBACK
// ============================================================================

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

  const rate =
    parsePositiveRate(
      data?.rates?.MZN ??
      data?.MZN ??
      data?.data?.rates?.MZN
    );

  if (!rate) {
    throw new Error(
      "MoneyConvert não retornou USD/MZN."
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

// ============================================================================
// MOTOR USD/MZN
// ============================================================================

async function getUsdMzn() {
  const providers = [
    getUsdMznFromAfricaApi,
    getUsdMznFromOpenERApi,
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

// ============================================================================
// COINBASE — USDT/USD
// ============================================================================

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
      "Coinbase não retornou USDT/USD."
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

// ============================================================================
// COINGECKO — USDT/USD
// ============================================================================

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
      "CoinGecko não retornou USDT/USD."
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

// ============================================================================
// MOTOR USDT/USD
// ============================================================================

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

  // USDT é tratado como paridade apenas
  // se os provedores de USDT/USD falharem.
  // Nunca é fallback para USD/MZN.
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

// ============================================================================
// TAXA FINAL
// ============================================================================

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
      "USD/MZN × USDT/USD produziu taxa inválida."
    );
  }

  const spread =
    Number.isFinite(
      RATE_SPREAD_PERCENT
    )
      ? RATE_SPREAD_PERCENT
      : 0;

  const finalRate =
    marketRate *
    (1 + spread / 100);

  const result = {
    value:
      roundMoney(
        finalRate,
        6
      ),

    rate:
      roundMoney(
        finalRate,
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

    spread:
      roundMoney(
        finalRate - marketRate,
        6
      ),

    spreadPercent:
      spread,

    source:
      `${usdMzn.source}+${usdtUsd.source}`,

    updatedAt:
      new Date().toISOString(),

    fxUpdatedAt:
      usdMzn.updatedAt,

    warning:
      usdtUsd.warning ||
      null
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

function topicToAddress(topic) {
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

function topicToAmount(topic) {
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
      "Transação ainda não possui receipt."
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

  const response =
    await fetchJson(
      `${TRON_HOST}/v1/transactions/${hash}/events?only_confirmed=true`,
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
    USDT_CONTRACT.toLowerCase();

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
      typeof to === "string"
    ) {
      destination =
        to.startsWith("T")
          ? to
          : topicToAddress(to);
    }

    if (
      destination !==
      treasury
    ) {
      continue;
    }

    let amount = null;

    if (
      typeof value ===
        "string" &&
      /^\d+$/.test(value)
    ) {
      amount =
        Number(
          BigInt(value)
        ) /
        10 ** USDT_DECIMALS;
    } else {
      amount =
        topicToAmount(value);
    }

    if (
      !Number.isFinite(amount) ||
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
// WALLETS TESOURARIA
// ============================================================================

async function getWallet(asset) {
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
      SELECT
        id,
        wallet_address,
        network,
        asset,
        balance,
        status,
        created_at,
        updated_at
      FROM wallets
      WHERE asset = ${normalized}
        AND (
          user_id IS NULL
          OR user_id = 0
        )
      ORDER BY id ASC
      LIMIT 1
    `;

  if (rows.length) {
    return rows[0];
  }

  const address =
    normalized === "USDT"
      ? getTreasuryAddress()
      : null;

  const created =
    await sql`
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
        ${normalized === "USDT"
          ? "TRON"
          : "INTERNAL"},
        ${normalized},
        0,
        'ACTIVE',
        NOW(),
        NOW(),
        NULL
      )
      RETURNING *
    `;

  return created[0];
}

async function getWalletBalances() {
  const rows =
    await sql`
      SELECT
        asset,
        balance,
        status
      FROM wallets
      WHERE (
        user_id IS NULL
        OR user_id = 0
      )
      AND asset IN ('MZN', 'USDT')
      ORDER BY asset
    `;

  let mzn = 0;
  let usdt = 0;

  for (
    const row of rows
  ) {
    if (
      row.asset === "MZN"
    ) {
      mzn =
        Number(row.balance) || 0;
    }

    if (
      row.asset === "USDT"
    ) {
      usdt =
        Number(row.balance) || 0;
    }
  }

  return {
    mzn:
      roundMoney(mzn, 2),

    usdt:
      roundMoney(usdt, 6)
  };
}

async function changeWalletBalance(
  asset,
  amount
) {
  const wallet =
    await getWallet(asset);

  const id =
    wallet.id;

  const updated =
    await sql`
      UPDATE wallets
      SET
        balance =
          COALESCE(balance, 0) +
          ${amount},
        updated_at = NOW()
      WHERE id = ${id}
      RETURNING *
    `;

  return updated[0];
}

// ============================================================================
// DEPÓSITO MZN MANUAL
// ============================================================================

async function registerMZNDeposit(
  body
) {
  const amount =
    positiveInteger(
      body.amount_mzn ??
      body.amount
    );

  if (!amount) {
    throw new Error(
      "Valor MZN inválido."
    );
  }

  if (
    amount < MIN_MZN ||
    amount > MAX_MZN
  ) {
    throw new Error(
      `O valor deve estar entre ${MIN_MZN} e ${MAX_MZN} MZN.`
    );
  }

  const source =
    normalizeSource(
      body.source ||
      body.method ||
      "MANUAL_APPROVED"
    );

  if (
    !isValidSource(source)
  ) {
    throw new Error(
      "Fonte de liquidez inválida."
    );
  }

  const reference =
    String(
      body.reference || ""
    ).trim() ||
    makeReference(
      "MZN-DEPOSIT"
    );

  const existing =
    await sql`
      SELECT *
      FROM transactions
      WHERE reference = ${reference}
      ORDER BY id DESC
      LIMIT 1
    `;

  if (existing.length) {
    return {
      success: true,
      existing: true,
      transaction:
        existing[0]
    };
  }

  const rows =
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
        NULL,
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
    confirmed: false,
    reference,
    transaction:
      rows[0]
  };
}

// ============================================================================
// CONFIRMAR MZN
// ============================================================================

async function confirmMZNDeposit(
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

  const rows =
    await sql`
      SELECT *
      FROM transactions
      WHERE reference = ${reference}
      AND type = 'DEPOSIT_MZN'
      ORDER BY id DESC
      LIMIT 1
    `;

  if (!rows.length) {
    throw new Error(
      "Depósito MZN não encontrado."
    );
  }

  const transaction =
    rows[0];

  if (
    transaction.status ===
    "COMPLETED"
  ) {
    return {
      success: true,
      confirmed: true,
      alreadyCompleted: true,
      reference,
      transaction
    };
  }

  if (
    transaction.status !==
    "PENDING"
  ) {
    throw new Error(
      `Depósito não pode ser confirmado no estado ${transaction.status}.`
    );
  }

  const amount =
    Number(
      transaction.amount
    );

  if (
    !Number.isFinite(amount) ||
    amount <= 0
  ) {
    throw new Error(
      "Valor do depósito inválido."
    );
  }

  await changeWalletBalance(
    "MZN",
    amount
  );

  const updated =
    await sql`
      UPDATE transactions
      SET status = 'COMPLETED'
      WHERE id = ${transaction.id}
      AND status = 'PENDING'
      RETURNING *
    `;

  if (!updated.length) {
    return {
      success: true,
      confirmed: true,
      reference
    };
  }

  return {
    success: true,
    confirmed: true,
    reference,
    amount,
    transaction:
      updated[0]
  };
}

// ============================================================================
// DEPÓSITO USDT — REGISTRAR
// ============================================================================

async function registerUSDTDeposit(
  body
) {
  const txHash =
    String(
      body.tx_hash ||
      body.txHash ||
      body.blockchain_tx_hash ||
      ""
    ).trim();

  if (
    !/^[a-fA-F0-9]{64}$/.test(
      txHash
    )
  ) {
    throw new Error(
      "TX hash TRON inválido."
    );
  }

  const reference =
    String(
      body.reference || ""
    ).trim() ||
    makeReference(
      "USDT-DEPOSIT"
    );

  const existing =
    await sql`
      SELECT *
      FROM transactions
      WHERE blockchain_tx_hash = ${txHash}
      OR reference = ${reference}
      ORDER BY id DESC
      LIMIT 1
    `;

  if (existing.length) {
    return {
      success: true,
      existing: true,
      transaction:
        existing[0]
    };
  }

  const rows =
    await sql`
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
        NULL,
        'DEPOSIT_USDT',
        'USDT',
        0,
        'PENDING',
        ${reference},
        ${txHash},
        NOW()
      )
      RETURNING *
    `;

  return {
    success: true,
    confirmed: false,
    reference,
    transaction:
      rows[0]
  };
}

// ============================================================================
// CONFIRMAR USDT — BLOCKCHAIN REAL
// ============================================================================

async function confirmUSDTDeposit(
  body
) {
  const reference =
    String(
      body.reference || ""
    ).trim();

  let txHash =
    String(
      body.tx_hash ||
      body.txHash ||
      ""
    ).trim();

  let transaction = null;

  if (reference) {
    const rows =
      await sql`
        SELECT *
        FROM transactions
        WHERE reference = ${reference}
        AND type = 'DEPOSIT_USDT'
        ORDER BY id DESC
        LIMIT 1
      `;

    if (rows.length) {
      transaction =
        rows[0];

      txHash =
        txHash ||
        String(
          transaction.blockchain_tx_hash ||
          ""
        );
    }
  }

  if (!txHash) {
    throw new Error(
      "TX hash é obrigatório."
    );
  }

  const verified =
    await verifyUsdtTransfer(
      txHash
    );

  if (!transaction) {
    const existing =
      await sql`
        SELECT *
        FROM transactions
        WHERE blockchain_tx_hash = ${txHash}
        AND type = 'DEPOSIT_USDT'
        ORDER BY id DESC
        LIMIT 1
      `;

    transaction =
      existing[0] || null;
  }

  if (!transaction) {
    const created =
      await sql`
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
          NULL,
          'DEPOSIT_USDT',
          'USDT',
          ${verified.amount},
          'COMPLETED',
          ${reference || makeReference("USDT-DEPOSIT")},
          ${txHash},
          NOW()
        )
        RETURNING *
      `;

    await changeWalletBalance(
      "USDT",
      verified.amount
    );

    return {
      success: true,
      confirmed: true,
      blockchain:
        verified,
      transaction:
        created[0]
    };
  }

  if (
    transaction.status ===
    "COMPLETED"
  ) {
    return {
      success: true,
      confirmed: true,
      alreadyCompleted: true,
      blockchain:
        verified,
      transaction
    };
  }

  await changeWalletBalance(
    "USDT",
    verified.amount
  );

  const updated =
    await sql`
      UPDATE transactions
      SET
        status = 'COMPLETED',
        amount = ${verified.amount},
        blockchain_tx_hash = ${txHash}
      WHERE id = ${transaction.id}
      AND status = 'PENDING'
      RETURNING *
    `;

  return {
    success: true,
    confirmed: true,
    blockchain:
      verified,
    transaction:
      updated[0] || transaction
  };
}

// ============================================================================
// CONVERSÃO MZN -> USDT
// ============================================================================

async function convertMZNToUSDT(
  body
) {
  const amountMZN =
    positiveInteger(
      body.amount_mzn ??
      body.amount
    );

  if (!amountMZN) {
    throw new Error(
      "Valor MZN inválido."
    );
  }

  if (
    amountMZN < MIN_MZN ||
    amountMZN > MAX_MZN
  ) {
    throw new Error(
      `A conversão deve estar entre ${MIN_MZN} e ${MAX_MZN} MZN.`
    );
  }

  const rate =
    await getRealUsdtMznRate();

  const amountUSDT =
    roundMoney(
      amountMZN /
        Number(rate.value),
      6
    );

  if (
    amountUSDT <= 0
  ) {
    throw new Error(
      "Quantidade USDT inválida."
    );
  }

  const balances =
    await getWalletBalances();

  if (
    balances.mzn <
    amountMZN
  ) {
    throw new Error(
      `Fundo MZN insuficiente. Disponível: ${balances.mzn} MZN.`
    );
  }

  if (
    balances.usdt <
    amountUSDT
  ) {
    throw new Error(
      `USDT insuficiente. Disponível: ${balances.usdt} USDT.`
    );
  }

  const reference =
    String(
      body.reference || ""
    ).trim() ||
    makeReference(
      "CONVERSION"
    );

  // Débito MZN somente se houver saldo suficiente.
  const debit =
    await sql`
      UPDATE wallets
      SET
        balance =
          balance - ${amountMZN},
        updated_at = NOW()
      WHERE asset = 'MZN'
      AND (
        user_id IS NULL
        OR user_id = 0
      )
      AND balance >= ${amountMZN}
      RETURNING *
    `;

  if (!debit.length) {
    throw new Error(
      "Não foi possível reservar o MZN para a conversão."
    );
  }

  try {
    const credit =
      await sql`
        UPDATE wallets
        SET
          balance =
            balance - ${amountUSDT},
          updated_at = NOW()
        WHERE asset = 'USDT'
        AND (
          user_id IS NULL
          OR user_id = 0
        )
        AND balance >= ${amountUSDT}
        RETURNING *
      `;

    if (!credit.length) {
      await sql`
        UPDATE wallets
        SET
          balance =
            balance + ${amountMZN},
          updated_at = NOW()
        WHERE asset = 'MZN'
        AND (
          user_id IS NULL
          OR user_id = 0
        )
      `;

      throw new Error(
        "USDT insuficiente para completar a conversão."
      );
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
        NULL,
        'CONVERSION_MZN_USDT',
        'USDT',
        ${amountUSDT},
        'COMPLETED',
        ${reference},
        NOW()
      )
    `;

    return {
      success: true,
      reference,

      input: {
        amountMzn:
          amountMZN
      },

      output: {
        amountUsdt:
          amountUSDT
      },

      rate: {
        rate:
          rate.value,

        marketRate:
          rate.marketRate,

        usdMzn:
          rate.usdMzn,

        usdtUsd:
          rate.usdtUsd,

        source:
          rate.source,

        updatedAt:
          rate.updatedAt
      }
    };
  } catch (error) {
    throw error;
  }
}

// ============================================================================
// RESERVA USDT
// ============================================================================

async function reserveUSDT(
  amount,
  reference
) {
  const value =
    positiveNumber(amount);

  if (!value) {
    throw new Error(
      "Quantidade USDT inválida."
    );
  }

  const ref =
    String(
      reference || ""
    ).trim() ||
    makeReference(
      "USDT-RESERVE"
    );

  const existing =
    await sql`
      SELECT *
      FROM transactions
      WHERE reference = ${ref}
      AND type = 'USDT_RESERVATION'
      ORDER BY id DESC
      LIMIT 1
    `;

  if (existing.length) {
    return {
      success: true,
      existing: true,
      transaction:
        existing[0]
    };
  }

  const wallet =
    await getWallet("USDT");

  const balance =
    Number(wallet.balance) || 0;

  if (
    balance <
    value
  ) {
    throw new Error(
      "USDT disponível insuficiente."
    );
  }

  const updated =
    await sql`
      UPDATE wallets
      SET
        balance =
          balance - ${value},
        updated_at = NOW()
      WHERE id = ${wallet.id}
      AND balance >= ${value}
      RETURNING *
    `;

  if (!updated.length) {
    throw new Error(
      "Não foi possível reservar USDT."
    );
  }

  const tx =
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
        NULL,
        'USDT_RESERVATION',
        'USDT',
        ${value},
        'PENDING',
        ${ref},
        NOW()
      )
      RETURNING *
    `;

  return {
    success: true,
    reference: ref,
    reserved:
      value,
    transaction:
      tx[0]
  };
}

// ============================================================================
// LIBERAR RESERVA
// ============================================================================

async function releaseReservation(
  body
) {
  const reference =
    String(
      body.reference ||
      body.reservation_reference ||
      ""
    ).trim();

  if (!reference) {
    throw new Error(
      "reference é obrigatória."
    );
  }

  const rows =
    await sql`
      SELECT *
      FROM transactions
      WHERE reference = ${reference}
      AND type = 'USDT_RESERVATION'
      ORDER BY id DESC
      LIMIT 1
    `;

  if (!rows.length) {
    throw new Error(
      "Reserva não encontrada."
    );
  }

  const reservation =
    rows[0];

  if (
    reservation.status !==
    "PENDING"
  ) {
    return {
      success: true,
      alreadyProcessed: true,
      transaction:
        reservation
    };
  }

  const amount =
    Number(
      reservation.amount
    );

  await changeWalletBalance(
    "USDT",
    amount
  );

  const updated =
    await sql`
      UPDATE transactions
      SET status = 'CANCELLED'
      WHERE id = ${reservation.id}
      AND status = 'PENDING'
      RETURNING *
    `;

  return {
    success: true,
    released:
      amount,
    transaction:
      updated[0] ||
      reservation
  };
}

// ============================================================================
// FONTES DE LIQUIDEZ
// ============================================================================

async function getLiquiditySources() {
  const balances =
    await getWalletBalances();

  let treasuryAddress = null;

  try {
    treasuryAddress =
      getTreasuryAddress();
  } catch {
    treasuryAddress =
      null;
  }

  return {
    success: true,

    sources: [
      {
        id:
          "TREASURY_TRON",
        type:
          "USDT_TRON",
        name:
          "Tesouraria USDTMZ",
        configured:
          Boolean(
            treasuryAddress
          ),
        address:
          treasuryAddress,
        asset:
          "USDT",
        network:
          "TRON/TRC20",
        balance:
          balances.usdt
      },

      {
        id:
          "PAGAR_MPESA",
        type:
          "MPESA_BUSINESS",
        name:
          "Pagar M-Pesa",
        configured:
          pagarConfigured(),
        asset:
          "MZN"
      },

      {
        id:
          "PAGAR_EMOLA",
        type:
          "EMOLA_BUSINESS",
        name:
          "Pagar e-Mola",
        configured:
          pagarConfigured(),
        asset:
          "MZN"
      },

      {
        id:
          "LIQUIDITY_PARTNER",
        type:
          "LIQUIDITY_PARTNER",
        name:
          "Parceiro externo de liquidez",
        configured:
          Boolean(
            process.env.USDTMZ_LIQUIDITY_PARTNER
          ),
        asset:
          "USDT"
      }
    ]
  };
}

// ============================================================================
// REGISTRAR FUNDING
// ============================================================================

async function registerFunding(
  body
) {
  const asset =
    String(
      body.asset || ""
    )
      .trim()
      .toUpperCase();

  if (
    asset !== "MZN" &&
    asset !== "USDT"
  ) {
    throw new Error(
      "Asset deve ser MZN ou USDT."
    );
  }

  const amount =
    positiveNumber(
      body.amount
    );

  if (!amount) {
    throw new Error(
      "amount inválido."
    );
  }

  const source =
    normalizeSource(
      body.source ||
      "MANUAL_APPROVED"
    );

  if (
    !isValidSource(source)
  ) {
    throw new Error(
      "Fonte de liquidez inválida."
    );
  }

  const reference =
    String(
      body.reference || ""
    ).trim() ||
    makeReference(
      "FUNDING"
    );

  const existing =
    await sql`
      SELECT *
      FROM transactions
      WHERE reference = ${reference}
      LIMIT 1
    `;

  if (existing.length) {
    return {
      success: true,
      existing: true,
      transaction:
        existing[0]
    };
  }

  const tx =
    await sql`
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
        NULL,
        'FUNDING',
        ${asset},
        ${amount},
        'COMPLETED',
        ${reference},
        ${body.tx_hash || null},
        NOW()
      )
      RETURNING *
    `;

  await changeWalletBalance(
    asset,
    amount
  );

  return {
    success: true,
    reference,
    amount,
    asset,
    source,
    transaction:
      tx[0]
  };
}

// ============================================================================
// DASHBOARD
// ============================================================================

async function getDashboard() {
  const balances =
    await getWalletBalances();

  let rate = null;

  try {
    rate =
      await getRealUsdtMznRate();
  } catch (error) {
    rate = {
      error:
        error?.message ||
        "Motor cambial indisponível."
    };
  }

  let tronAddress = null;

  try {
    tronAddress =
      getTreasuryAddress();
  } catch {
    tronAddress =
      null;
  }

  let trx = 0;

  if (tronAddress) {
    try {
      const tronWeb =
        getTronWeb();

      const sun =
        await tronWeb.trx.getBalance(
          tronAddress
        );

      trx =
        Number(sun) /
        1_000_000;
    } catch {
      trx = 0;
    }
  }

  const reservedRows =
    await sql`
      SELECT
        COALESCE(
          SUM(amount),
          0
        ) AS reserved
      FROM transactions
      WHERE type = 'USDT_RESERVATION'
      AND status = 'PENDING'
    `;

  const reserved =
    Number(
      reservedRows[0]?.reserved || 0
    );

  const available =
    Math.max(
      0,
      balances.usdt
    );

  let state =
    "SEM LIQUIDEZ";

  if (
    balances.usdt > 0 &&
    balances.mzn > 0
  ) {
    state =
      "LIQUIDEZ DISPONÍVEL";
  } else if (
    balances.usdt > 0
  ) {
    state =
      "USDT DISPONÍVEL";
  } else if (
    balances.mzn > 0
  ) {
    state =
      "MZN DISPONÍVEL";
  }

  return {
    success: true,

    treasury: {
      mzn:
        balances.mzn,

      usdt:
        balances.usdt,

      trx:
        roundMoney(trx, 6),

      reservedUsdt:
        roundMoney(
          reserved,
          6
        ),

      availableUsdt:
        roundMoney(
          available,
          6
        ),

      state
    },

    wallet: {
      address:
        tronAddress,

      network:
        "TRON Mainnet",

      asset:
        "USDT",

      standard:
        "TRC-20",

      contract:
        USDT_CONTRACT
    },

    rate
  };
}

// ============================================================================
// OPERAÇÕES RECENTES
// ============================================================================

async function getRecentOperations() {
  const rows =
    await sql`
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
      ORDER BY id DESC
      LIMIT 50
    `;

  return {
    success: true,
    operations:
      rows
  };
}

// ============================================================================
// DEPÓSITOS PENDENTES
// ============================================================================

async function getPendingDeposits() {
  const rows =
    await sql`
      SELECT
        id,
        type,
        asset,
        amount,
        status,
        reference,
        blockchain_tx_hash,
        created_at
      FROM transactions
      WHERE status = 'PENDING'
      ORDER BY id ASC
      LIMIT 100
    `;

  return {
    success: true,
    deposits:
      rows
  };
}

// ============================================================================
// TAXA
// ============================================================================

async function rateResponse(force = false) {
  const rate =
    await getRealUsdtMznRate(
      force
    );

  return {
    success: true,

    data: {
      rate:
        rate.value,

      marketRate:
        rate.marketRate,

      usdMzn:
        rate.usdMzn,

      usdtUsd:
        rate.usdtUsd,

      spread:
        rate.spread,

      spreadPercent:
        rate.spreadPercent,

      source:
        rate.source,

      updatedAt:
        rate.updatedAt,

      fxUpdatedAt:
        rate.fxUpdatedAt,

      warning:
        rate.warning
    }
  };
}

// ============================================================================
// ROTEADOR PRINCIPAL
// ============================================================================

export default async function handler(
  req,
  res
) {
  try {
    // ------------------------------------------------------------------------
    // SOMENTE ADMIN
    // ------------------------------------------------------------------------

    const admin =
      requireAdmin(req);

    if (
      req.method !== "GET" &&
      req.method !== "POST"
    ) {
      return sendJson(
        res,
        405,
        {
          success: false,
          error:
            "Método não permitido."
        }
      );
    }

    const body =
      req.method === "POST"
        ? await readBody(req)
        : {};

    const url =
      new URL(
        req.url,
        "http://localhost"
      );

    const action =
      String(
        body.action ||
        url.searchParams.get(
          "action"
        ) ||
        "dashboard"
      )
        .trim()
        .toLowerCase();

    // ========================================================================
    // RATE
    // ========================================================================

    if (
      action === "rate" ||
      action === "exchange_rate" ||
      action === "fx_rate"
    ) {
      return sendJson(
        res,
        200,
        await rateResponse(
          true
        )
      );
    }

    // ========================================================================
    // DASHBOARD
    // ========================================================================

    if (
      action === "dashboard"
    ) {
      return sendJson(
        res,
        200,
        await getDashboard()
      );
    }

    // ========================================================================
    // FONTES DE LIQUIDEZ
    // ========================================================================

    if (
      action === "sources" ||
      action === "liquidity_sources"
    ) {
      return sendJson(
        res,
        200,
        await getLiquiditySources()
      );
    }

    // ========================================================================
    // OPERAÇÕES
    // ========================================================================

    if (
      action === "operations" ||
      action === "recent_operations"
    ) {
      return sendJson(
        res,
        200,
        await getRecentOperations()
      );
    }

    // ========================================================================
    // PENDING DEPOSITS
    // ========================================================================

    if (
      action === "pending_deposits"
    ) {
      return sendJson(
        res,
        200,
        await getPendingDeposits()
      );
    }

    // ========================================================================
    // PAGAR TOP-UP
    // ========================================================================

    if (
      action ===
        "create_pagar_treasury_topup" ||
      action ===
        "pagar_treasury_topup"
    ) {
      return sendJson(
        res,
        200,
        await createPagarTreasuryTopup(
          body
        )
      );
    }

    // ========================================================================
    // PAGAR STATUS
    // ========================================================================

    if (
      action ===
        "check_pagar_treasury_topup" ||
      action ===
        "pagar_treasury_status"
    ) {
      return sendJson(
        res,
        200,
        await checkPagarTreasuryTopup(
          body
        )
      );
    }

    // ========================================================================
    // MZN MANUAL/BANK
    // ========================================================================

    if (
      action ===
        "register_mzn_deposit"
    ) {
      return sendJson(
        res,
        200,
        await registerMZNDeposit(
          body
        )
      );
    }

    if (
      action ===
        "confirm_mzn_deposit"
    ) {
      return sendJson(
        res,
        200,
        await confirmMZNDeposit(
          body
        )
      );
    }

    // ========================================================================
    // USDT TRC20
    // ========================================================================

    if (
      action ===
        "register_usdt_deposit"
    ) {
      return sendJson(
        res,
        200,
        await registerUSDTDeposit(
          body
        )
      );
    }

    if (
      action ===
        "confirm_usdt_deposit"
    ) {
      return sendJson(
        res,
        200,
        await confirmUSDTDeposit(
          body
        )
      );
    }

    // ========================================================================
    // CONVERSÃO
    // ========================================================================

    if (
      action ===
        "convert_mzn_to_usdt"
    ) {
      return sendJson(
        res,
        200,
        await convertMZNToUSDT(
          body
        )
      );
    }

    // ========================================================================
    // RESERVA
    // ========================================================================

    if (
      action ===
        "reserve_usdt"
    ) {
      const amount =
        positiveNumber(
          body.amount_usdt ??
          body.amount
        );

      const reference =
        body.reference ||
        makeReference(
          "USDT-RESERVE"
        );

      return sendJson(
        res,
        200,
        await reserveUSDT(
          amount,
          reference
        )
      );
    }

    // ========================================================================
    // LIBERAR RESERVA
    // ========================================================================

    if (
      action ===
        "release_reservation"
    ) {
      return sendJson(
        res,
        200,
        await releaseReservation(
          body
        )
      );
    }

    // ========================================================================
    // FUNDING
    // ========================================================================

    if (
      action ===
        "register_funding"
    ) {
      return sendJson(
        res,
        200,
        await registerFunding(
          body
        )
      );
    }

    // ========================================================================
    // ENDPOINT DESCONHECIDO
    // ========================================================================

    return sendJson(
      res,
      400,
      {
        success: false,
        error:
          `Ação "${action}" não reconhecida.`,
        admin:
          admin.email
      }
    );

  } catch (error) {
    console.error(
      "USDTMZ API06 ERROR:",
      error
    );

    const status =
      Number(
        error?.statusCode ||
        error?.status ||
        500
      );

    return sendJson(
      res,
      status >= 400 &&
      status < 600
        ? status
        : 500,
      {
        success: false,
        error:
          error?.message ||
          "Erro interno da Central Admin."
      }
    );
  }
}
```0
