// api/admin-withdrawals.js
// USDTMZ — API06 CENTRAL ADMIN / TESOURARIA
// API06 — NÃO CRIAR API13
//
// TESOURARIA REAL
// - Neon/PostgreSQL
// - Pay.co.mz
// - TRON/TRC20
// - CoinGecko para referência FX
// - Depósitos
// - Conversão MZN -> USDT real
// - Reservas
// - Retiradas com aprovação
// - Webhooks Pay
//
// REGRAS:
// - NÃO cria USDT artificialmente.
// - NÃO envia retirada sem aprovação.
// - NÃO confia em confirmação do navegador.
// - NÃO expõe credenciais.
// - PAY deve ser confirmado pelo servidor.
// - USDT deve ser confirmado na blockchain.
// - Valores reservados não podem ser reutilizados.
// - Eventos externos são idempotentes.

export const config = {
  api: {
    bodyParser: false
  }
};

import {
  createHmac,
  timingSafeEqual,
  randomBytes
} from "node:crypto";

import { neon } from "@neondatabase/serverless";
import { TronWeb } from "tronweb";

const sql = neon(process.env.DATABASE_URL);

const COOKIE = "usdtmz_admin_session";

const MIN_MZN = 20;
const MAX_MZN = 40000;

const USDT_DECIMALS = 6;
const USDT_FACTOR = 10 ** USDT_DECIMALS;

const FX_CACHE_SECONDS =
  Number(process.env.FX_CACHE_SECONDS || 60);

const FX_MARKET_URL =
  process.env.FX_MARKET_URL ||
  "https://api.coingecko.com/api/v3/simple/price?ids=tether&vs_currencies=mzn";

const CONTRACT =
  process.env.USDT_TRON_CONTRACT ||
  "TR7NHqKQxGTCi8q8ZY4pL8otSzgjLj6t";

const TRON_HOST =
  process.env.TRON_HOST ||
  "https://api.trongrid.io";

const PAY_BASE =
  process.env.PAY_API_BASE_URL ||
  "https://pay.co.mz/api/public/v1";

const PAY_TIMEOUT_MS =
  Number(process.env.PAY_TIMEOUT_MS || 20000);

const DEPOSIT_SOURCES = [
  "MPESA",
  "EMOLA",
  "BANK",
  "USDT_TRON",
  "EXTERNAL",
  "MANUAL"
];

const LIQUIDITY_SOURCES = [
  "MPESA_BUSINESS",
  "EMOLA_BUSINESS",
  "BANK",
  "USDT_TRON",
  "EXTERNAL_WALLET",
  "LIQUIDITY_PARTNER",
  "USDT_PURCHASE",
  "BINANCE",
  "KOTANI",
  "REDPAY",
  "MANUAL_APPROVED"
];

let tablesReady = false;
let tablesPromise = null;

/* =========================================================
   HELPERS
========================================================= */

const json = (res, status, data) => {
  res.status(status);

  res.setHeader(
    "Content-Type",
    "application/json"
  );

  res.setHeader(
    "Cache-Control",
    "no-store"
  );

  res.end(
    JSON.stringify(data)
  );
};

const clean = v =>
  String(v ?? "").trim();

const upper = v =>
  clean(v).toUpperCase();

const number = v => {
  const n = Number(v);

  return Number.isFinite(n)
    ? n
    : null;
};

const positive = v => {
  const n = number(v);

  return n !== null && n > 0
    ? n
    : null;
};

const round = (v, d = 6) =>
  Math.round(
    Number(v) * 10 ** d
  ) /
  10 ** d;

const reference = prefix =>
  `${prefix}-${Date.now()}-${randomBytes(8)
    .toString("hex")
    .toUpperCase()}`;

const validSource = source =>
  DEPOSIT_SOURCES.includes(
    upper(source)
  );

function safeEqual(a, b) {
  const x =
    Buffer.from(String(a));

  const y =
    Buffer.from(String(b));

  if (
    x.length !== y.length
  ) {
    return false;
  }

  return timingSafeEqual(
    x,
    y
  );
}

function cookies(req) {
  const out = {};

  for (
    const item of String(
      req.headers?.cookie || ""
    ).split(";")
  ) {
    const i =
      item.indexOf("=");

    if (i < 0) continue;

    const key =
      item.slice(0, i).trim();

    try {
      out[key] =
        decodeURIComponent(
          item
            .slice(i + 1)
            .trim()
        );
    } catch {
      out[key] =
        item
          .slice(i + 1)
          .trim();
    }
  }

  return out;
}

function errorWithStatus(
  message,
  statusCode = 400
) {
  const e =
    new Error(message);

  e.statusCode =
    statusCode;

  return e;
}

/* =========================================================
   ADMIN SESSION
========================================================= */

function admin(req) {
  const token =
    cookies(req)[COOKIE];

  const secret =
    process.env.ADMIN_SESSION_SECRET;

  if (
    !token ||
    !secret
  ) {
    return null;
  }

  const parts =
    token.split(".");

  if (
    parts.length !== 2
  ) {
    return null;
  }

  const [
    payload,
    signature
  ] = parts;

  const expected =
    createHmac(
      "sha256",
      secret
    )
      .update(payload)
      .digest("base64url");

  if (
    !safeEqual(
      signature,
      expected
    )
  ) {
    return null;
  }

  try {
    const data =
      JSON.parse(
        Buffer.from(
          payload,
          "base64url"
        ).toString()
      );

    if (
      data?.id !== "admin" ||
      !data?.email ||
      Number(data?.exp) <=
        Date.now()
    ) {
      return null;
    }

    return data;
  } catch {
    return null;
  }
}

function requireAdmin(req) {
  const session =
    admin(req);

  if (!session) {
    throw errorWithStatus(
      "Acesso permitido somente ao administrador.",
      401
    );
  }

  return session;
}

/* =========================================================
   REQUEST BODY
========================================================= */

async function requestBody(req) {
  if (
    req.body &&
    typeof req.body === "object"
  ) {
    return req.body;
  }

  let raw = "";

  for await (
    const chunk of req
  ) {
    raw += chunk.toString();
  }

  if (!raw) {
    return {};
  }

  try {
    return JSON.parse(raw);
  } catch {
    throw errorWithStatus(
      "JSON inválido.",
      400
    );
  }
}

async function requestRawBody(req) {
  let raw = "";

  for await (
    const chunk of req
  ) {
    raw += chunk.toString();
  }

  return raw;
}

/* =========================================================
   HTTP
========================================================= */

async function fetchJson(
  url,
  options = {},
  timeout = 20000
) {
  const controller =
    new AbortController();

  const timer =
    setTimeout(
      () =>
        controller.abort(),
      timeout
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

    if (
      !response.ok
    ) {
      const e =
        new Error(
          data?.message ||
          data?.error ||
          `HTTP ${response.status}`
        );

      e.statusCode =
        response.status;

      e.data =
        data;

      throw e;
    }

    return data;
  } catch (e) {
    if (
      e?.name ===
      "AbortError"
    ) {
      const err =
        new Error(
          "Tempo limite atingido ao comunicar com o provedor."
        );

      err.code =
        "UPSTREAM_TIMEOUT";

      err.statusCode =
        504;

      throw err;
    }

    throw e;
  } finally {
    clearTimeout(timer);
  }
}

/* =========================================================
   DATABASE
========================================================= */

async function ensureTables() {
  if (tablesReady) {
    return;
  }

  if (tablesPromise) {
    return tablesPromise;
  }

  tablesPromise =
    (async () => {

      await sql`
        CREATE TABLE IF NOT EXISTS treasury_wallet (
          id INTEGER PRIMARY KEY,
          mzn NUMERIC(30,8) NOT NULL DEFAULT 0,
          usdt NUMERIC(30,8) NOT NULL DEFAULT 0,
          trx NUMERIC(30,8) NOT NULL DEFAULT 0,
          reserved_usdt NUMERIC(30,8) NOT NULL DEFAULT 0,
          reserved_mzn NUMERIC(30,8) NOT NULL DEFAULT 0,
          updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )
      `;

      await sql`
        ALTER TABLE treasury_wallet
        ADD COLUMN IF NOT EXISTS
        reserved_mzn NUMERIC(30,8)
        NOT NULL DEFAULT 0
      `;

      await sql`
        INSERT INTO treasury_wallet(id)
        VALUES(1)
        ON CONFLICT(id)
        DO NOTHING
      `;

      await sql`
        CREATE TABLE IF NOT EXISTS treasury_deposits (
          id BIGSERIAL PRIMARY KEY,
          order_id TEXT UNIQUE NOT NULL,
          source TEXT NOT NULL,
          amount NUMERIC(30,8) NOT NULL,
          currency TEXT NOT NULL,
          reference TEXT,
          payment_phone TEXT,
          tx_hash TEXT,
          status TEXT NOT NULL DEFAULT 'PENDING',
          rate NUMERIC(30,10),
          usdt_amount NUMERIC(30,8),
          fee NUMERIC(30,8) NOT NULL DEFAULT 0,
          net_amount NUMERIC(30,8),
          provider_id TEXT,
          message TEXT,
          created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
          updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )
      `;

      await sql`
        ALTER TABLE treasury_deposits
        ADD COLUMN IF NOT EXISTS
        fee NUMERIC(30,8)
        NOT NULL DEFAULT 0
      `;

      await sql`
        ALTER TABLE treasury_deposits
        ADD COLUMN IF NOT EXISTS
        net_amount NUMERIC(30,8)
      `;

      await sql`
        ALTER TABLE treasury_deposits
        ADD COLUMN IF NOT EXISTS
        provider_id TEXT
      `;

      await sql`
        CREATE TABLE IF NOT EXISTS treasury_conversions (
          id BIGSERIAL PRIMARY KEY,
          reference TEXT UNIQUE NOT NULL,
          deposit_id BIGINT,
          mzn_amount NUMERIC(30,8) NOT NULL,
          usdt_amount NUMERIC(30,8) NOT NULL,
          rate NUMERIC(30,10) NOT NULL,
          status TEXT NOT NULL DEFAULT 'COMPLETED',
          created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )
      `;

      await sql`
        CREATE TABLE IF NOT EXISTS treasury_reservations (
          id BIGSERIAL PRIMARY KEY,
          reference TEXT UNIQUE NOT NULL,
          usdt_amount NUMERIC(30,8) NOT NULL,
          status TEXT NOT NULL DEFAULT 'RESERVED',
          reason TEXT,
          created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )
      `;

      await sql`
        CREATE TABLE IF NOT EXISTS blockchain_transactions (
          id BIGSERIAL PRIMARY KEY,
          tx_hash TEXT UNIQUE NOT NULL,
          asset TEXT NOT NULL,
          amount NUMERIC(30,8),
          direction TEXT,
          address TEXT,
          confirmations INTEGER DEFAULT 0,
          status TEXT NOT NULL DEFAULT 'CONFIRMED',
          created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )
      `;

      await sql`
        CREATE TABLE IF NOT EXISTS transactions (
          id BIGSERIAL PRIMARY KEY,
          user_id TEXT,
          type TEXT,
          asset TEXT,
          amount NUMERIC(30,8),
          status TEXT,
          reference TEXT UNIQUE,
          provider TEXT,
          provider_reference TEXT,
          tx_hash TEXT,
          created_at TIMESTAMPTZ DEFAULT NOW()
        )
      `;

      await sql`
        CREATE TABLE IF NOT EXISTS treasury_withdrawals (
          id BIGSERIAL PRIMARY KEY,
          reference TEXT UNIQUE NOT NULL,
          method TEXT NOT NULL,
          amount NUMERIC(30,8) NOT NULL,
          currency TEXT NOT NULL DEFAULT 'MZN',
          destination TEXT,
          status TEXT NOT NULL DEFAULT 'PENDING',
          approval_status TEXT NOT NULL DEFAULT 'PENDING',
          provider TEXT,
          provider_reference TEXT,
          provider_id TEXT,
          fee NUMERIC(30,8) NOT NULL DEFAULT 0,
          net_amount NUMERIC(30,8),
          message TEXT,
          created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
          updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )
      `;

      await sql`
        CREATE TABLE IF NOT EXISTS pay_webhook_events (
          id BIGSERIAL PRIMARY KEY,
          event_id TEXT UNIQUE NOT NULL,
          event_name TEXT,
          created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )
      `;

      await sql`
        CREATE INDEX IF NOT EXISTS
        transactions_provider_reference_idx
        ON transactions(provider, provider_reference)
      `;

      await sql`
        CREATE INDEX IF NOT EXISTS
        treasury_withdrawals_provider_reference_idx
        ON treasury_withdrawals(
          provider,
          provider_reference
        )
      `;

      await sql`
        CREATE UNIQUE INDEX IF NOT EXISTS
        treasury_deposits_reference_unique_idx
        ON treasury_deposits(reference)
        WHERE reference IS NOT NULL
      `;

      tablesReady = true;
    })();

  try {
    await tablesPromise;
  } catch (e) {
    tablesPromise = null;
    throw e;
  }
}

/* =========================================================
   TREASURY
========================================================= */

async function treasury() {
  const [row] =
    await sql`
      SELECT *
      FROM treasury_wallet
      WHERE id=1
    `;

  return {
    mzn:
      Number(row?.mzn || 0),

    usdt:
      Number(row?.usdt || 0),

    trx:
      Number(row?.trx || 0),

    reserved_usdt:
      Number(
        row?.reserved_usdt || 0
      ),

    reserved_mzn:
      Number(
        row?.reserved_mzn || 0
      )
  };
}

async function changeWallet(
  asset,
  amount
) {
  const value =
    Number(amount);

  if (
    !Number.isFinite(value) ||
    value === 0
  ) {
    throw new Error(
      "Valor inválido."
    );
  }

  if (asset === "MZN") {
    const [row] =
      await sql`
        UPDATE treasury_wallet
        SET
          mzn=mzn+${value},
          updated_at=NOW()
        WHERE id=1
        RETURNING *
      `;

    return row;
  }

  if (asset === "USDT") {
    const [row] =
      await sql`
        UPDATE treasury_wallet
        SET
          usdt=usdt+${value},
          updated_at=NOW()
        WHERE id=1
        RETURNING *
      `;

    return row;
  }

  if (asset === "TRX") {
    const [row] =
      await sql`
        UPDATE treasury_wallet
        SET
          trx=trx+${value},
          updated_at=NOW()
        WHERE id=1
        RETURNING *
      `;

    return row;
  }

  throw new Error(
    "Ativo inválido."
  );
}

/* =========================================================
   FX
========================================================= */

let fxMemoryCache = {
  rate: null,
  timestamp: 0,
  source: null
};

async function marketFX() {
  const now =
    Date.now();

  if (
    fxMemoryCache.rate &&
    now -
      fxMemoryCache.timestamp <
      FX_CACHE_SECONDS * 1000
  ) {
    return {
      rate:
        fxMemoryCache.rate,

      source:
        fxMemoryCache.source,

      timestamp:
        new Date(
          fxMemoryCache.timestamp
        ).toISOString(),

      cached: true
    };
  }

  const data =
    await fetchJson(
      FX_MARKET_URL,
      {
        headers: {
          Accept:
            "application/json"
        }
      },
      10000
    );

  const rate =
    Number(
      data?.tether?.mzn
    );

  if (
    !Number.isFinite(rate) ||
    rate <= 0
  ) {
    throw new Error(
      "Fonte FX não devolveu uma taxa MZN/USDT válida."
    );
  }

  fxMemoryCache = {
    rate,
    timestamp: now,
    source:
      "COINGECKO_MARKET"
  };

  return {
    rate,
    source:
      "COINGECKO_MARKET",
    timestamp:
      new Date(now).toISOString(),
    cached: false
  };
}

function calculateUSDT(
  mzn,
  rate
) {
  return round(
    Number(mzn) /
      Number(rate),
    USDT_DECIMALS
  );
}

async function fx() {
  return marketFX();
}

/* =========================================================
   TRON
========================================================= */

function tronAddress(address) {
  try {
    return Boolean(
      address &&
      TronWeb.isAddress(
        String(address).trim()
      )
    );
  } catch {
    return false;
  }
}

function tron() {
  const options = {
    fullHost:
      TRON_HOST
  };

  if (
    process.env.TRON_PRO_API_KEY
  ) {
    options.headers = {
      "TRON-PRO-API-KEY":
        process.env.TRON_PRO_API_KEY
    };
  }

  return new TronWeb(
    options
  );
}

function treasuryAddress() {
  const address =
    clean(
      process.env.TREASURY_TRON_ADDRESS ||
      process.env.USDTMZ_TRON_WALLET_ADDRESS ||
      process.env.TRON_TREASURY_ADDRESS
    );

  if (
    !tronAddress(address)
  ) {
    throw new Error(
      "Endereço TRON da tesouraria inválido."
    );
  }

  return address;
}

function validateUSDTContract() {
  if (
    !tronAddress(
      CONTRACT
    )
  ) {
    throw new Error(
      "Contrato USDT TRON inválido."
    );
  }
}

async function tronUSDTBalance() {
  validateUSDTContract();

  const address =
    treasuryAddress();

  const tw =
    tron();

  const contract =
    await tw
      .contract()
      .at(CONTRACT);

  const balance =
    await contract
      .balanceOf(address)
      .call();

  const raw =
    balance?.toString?.() ||
    String(balance);

  const integer =
    BigInt(
      String(raw)
    );

  return (
    Number(integer) /
    USDT_FACTOR
  );
}

async function tronTRXBalance() {
  const address =
    treasuryAddress();

  const data =
    await fetchJson(
      `${TRON_HOST}/v1/accounts/${address}`,
      {
        headers:
          process.env.TRON_PRO_API_KEY
            ? {
                "TRON-PRO-API-KEY":
                  process.env.TRON_PRO_API_KEY
              }
            : {}
      },
      15000
    );

  return (
    Number(
      data?.data?.[0]?.balance || 0
    ) / 1e6
  );
}

/* =========================================================
   LIQUIDEZ REAL
========================================================= */

async function realLiquidity() {
  const internal =
    await treasury();

  let chainUSDT = null;
  let chainTRX = null;

  try {
    chainUSDT =
      await tronUSDTBalance();
  } catch (e) {
    console.error(
      "TRON USDT:",
      e.message
    );
  }

  try {
    chainTRX =
      await tronTRXBalance();
  } catch (e) {
    console.error(
      "TRON TRX:",
      e.message
    );
  }

  const internalAvailable =
    Math.max(
      0,
      internal.usdt -
        internal.reserved_usdt
    );

  const realAvailable =
    chainUSDT === null
      ? 0
      : Math.min(
          internalAvailable,
          chainUSDT
        );

  return {
    internal_usdt:
      internal.usdt,

    reserved_usdt:
      internal.reserved_usdt,

    internal_available_usdt:
      internalAvailable,

    blockchain_usdt:
      chainUSDT,

    blockchain_trx:
      chainTRX,

    real_available_usdt:
      realAvailable,

    liquidity:
      realAvailable > 0
        ? "DISPONIVEL"
        : "SEM_LIQUIDEZ"
  };
}

/* =========================================================
   PAY
========================================================= */

function payConfigured() {
  return Boolean(
    process.env.PAY_API_KEY &&
    process.env.PAY_WALLET_ID &&
    process.env.PAY_MERCHANT_ID
  );
}

async function pay(
  path,
  options = {}
) {
  if (!payConfigured()) {
    throw new Error(
      "Pay.co.mz não está configurado."
    );
  }

  const safeHeaders = {};

  if (
    options.headers?.[
      "Idempotency-Key"
    ]
  ) {
    safeHeaders[
      "Idempotency-Key"
    ] =
      String(
        options.headers[
          "Idempotency-Key"
        ]
      );
  }

  return fetchJson(
    `${PAY_BASE}${path}`,
    {
      method:
        options.method || "GET",

      body:
        options.body,

      headers: {
        Authorization:
          `Bearer ${process.env.PAY_API_KEY}`,

        "X-Wallet-Id":
          String(
            process.env.PAY_WALLET_ID
          ),

        "X-Merchant-Id":
          String(
            process.env.PAY_MERCHANT_ID
          ),

        Accept:
          "application/json",

        ...(options.body
          ? {
              "Content-Type":
                "application/json"
            }
          : {}),

        ...safeHeaders
      }
    },
    PAY_TIMEOUT_MS
  );
}

function payMethod(method) {
  const m =
    clean(method)
      .toLowerCase();

  if (m === "mpesa") {
    return "mpesa";
  }

  if (m === "emola") {
    throw new Error(
      "e-Mola ainda não está disponível em produção na PAY.co.mz."
    );
  }

  throw new Error(
    "Método Pay inválido."
  );
}

function payData(result) {
  return (
    result?.data &&
    typeof result.data === "object"
      ? result.data
      : result
  );
}

function extractPayReference(data) {
  return clean(
    data?.reference ||
    data?.transaction_reference ||
    data?.payment_reference
  );
}

async function findPayCharge(
  providerReference
) {
  const ref =
    clean(providerReference);

  if (!ref) {
    return null;
  }

  const result =
    await pay(
      "/charges?limit=100",
      {
        method: "GET"
      }
    );

  const rows =
    Array.isArray(
      result?.data
    )
      ? result.data
      : Array.isArray(result)
        ? result
        : [];

  return (
    rows.find(
      item =>
        extractPayReference(
          item
        ) === ref
    ) || null
  );
}

/* =========================================================
   DEPÓSITOS
========================================================= */

async function createDeposit(body) {
  const source =
    upper(
      body.source ||
      body.method
    );

  if (
    !validSource(source)
  ) {
    throw new Error(
      "Método de depósito inválido."
    );
  }

  if (
    source === "EMOLA"
  ) {
    throw new Error(
      "e-Mola ainda não está disponível em produção na PAY.co.mz."
    );
  }

  const amount =
    positive(
      body.amount
    );

  if (!amount) {
    throw new Error(
      "Valor inválido."
    );
  }

  const currency =
    upper(
      body.currency ||
      (
        source ===
        "USDT_TRON"
          ? "USDT"
          : "MZN"
      )
    );

  if (
    source === "MPESA" &&
    currency !== "MZN"
  ) {
    throw new Error(
      "Depósito M-Pesa deve usar MZN."
    );
  }

  if (
    source === "USDT_TRON" &&
    currency !== "USDT"
  ) {
    throw new Error(
      "Depósito USDT_TRON deve usar moeda USDT."
    );
  }

  const orderId =
    clean(
      body.order_id
    ) ||
    reference("DEP");

  const phone =
    clean(
      body.payment_phone ||
      body.phone
    ) || null;

  const txHash =
    clean(
      body.tx_hash ||
      body.txHash
    ) || null;

  if (
    source === "MPESA"
  ) {
    let normalized =
      phone
        ? phone.replace(
            /\D/g,
            ""
          )
        : "";

    if (
      /^\d{9}$/.test(
        normalized
      )
    ) {
      normalized =
        "258" + normalized;
    }

    if (
      !/^258(84|85)\d{7}$/.test(
        normalized
      )
    ) {
      throw new Error(
        "Número M-Pesa inválido. Use 84XXXXXXXX ou 85XXXXXXXX."
      );
    }
  }

  if (
    source === "USDT_TRON"
  ) {
    if (!txHash) {
      throw new Error(
        "Informe o TX Hash do depósito USDT."
      );
    }

    if (
      !/^[a-fA-F0-9]{64}$/.test(
        txHash
      )
    ) {
      throw new Error(
        "TX Hash TRON inválido."
      );
    }
  }

  const [
    existing
  ] =
    await sql`
      SELECT *
      FROM treasury_deposits
      WHERE order_id=${orderId}
      LIMIT 1
    `;

  if (existing) {
    return {
      success: true,
      existing: true,
      order: existing
    };
  }

  const [
    row
  ] =
    await sql`
      INSERT INTO treasury_deposits(
        order_id,
        source,
        amount,
        currency,
        payment_phone,
        tx_hash,
        status,
        message
      )
      VALUES(
        ${orderId},
        ${source},
        ${amount},
        ${currency},
        ${phone},
        ${txHash},
        'PENDING',
        'Depósito criado e aguardando confirmação.'
      )
      RETURNING *
    `;

  await sql`
    INSERT INTO transactions(
      type,
      asset,
      amount,
      status,
      reference,
      provider,
      tx_hash
    )
    VALUES(
      'DEPOSIT',
      ${currency},
      ${amount},
      'PENDING',
      ${orderId},
      ${source},
      ${txHash}
    )
    ON CONFLICT(reference)
    DO NOTHING
  `;

  return {
    success: true,
    created: true,
    order: row
  };
}

/* =========================================================
   TRON DEPOSIT
========================================================= */

function decodeTronAddress(
  value
) {
  const text =
    String(value || "");

  if (
    tronAddress(text)
  ) {
    return text;
  }

  if (
    /^[0-9a-fA-F]{40}$/.test(
      text
    )
  ) {
    try {
      return TronWeb.address.fromHex(
        "41" + text
      );
    } catch {
      return "";
    }
  }

  return "";
}

async function verifyUSDTDeposit(
  order
) {
  validateUSDTContract();

  if (!order.tx_hash) {
    throw new Error(
      "TX Hash não informado."
    );
  }

  const data =
    await fetchJson(
      `${TRON_HOST}/v1/transactions/${order.tx_hash}`,
      {
        headers:
          process.env.TRON_PRO_API_KEY
            ? {
                "TRON-PRO-API-KEY":
                  process.env.TRON_PRO_API_KEY
              }
            : {}
      },
      15000
    );

  const tx =
    data?.data?.[0];

  if (!tx) {
    throw new Error(
      "Transação TRON não encontrada."
    );
  }

  const contractRet =
    tx?.ret?.[0]?.contractRet;

  if (
    contractRet !== "SUCCESS"
  ) {
    throw new Error(
      "Transação TRON não foi concluída com sucesso."
    );
  }

  const event =
    await fetchJson(
      `${TRON_HOST}/v1/transactions/${order.tx_hash}/events`,
      {
        headers:
          process.env.TRON_PRO_API_KEY
            ? {
                "TRON-PRO-API-KEY":
                  process.env.TRON_PRO_API_KEY
              }
            : {}
      },
      15000
    );

  const transfers =
    Array.isArray(
      event?.data
    )
      ? event.data
      : [];

  const matchingTransfers =
    transfers.filter(
      x =>
        upper(
          x?.event_name
        ) === "TRANSFER" &&
        String(
          x?.contract_address || ""
        ).toLowerCase() ===
          CONTRACT.toLowerCase()
    );

  if (
    !matchingTransfers.length
  ) {
    throw new Error(
      "Transferência USDT TRC20 não encontrada."
    );
  }

  const expected =
    treasuryAddress();

  const transfer =
    matchingTransfers.find(
      x => {
        const to =
          decodeTronAddress(
            x?.result?.to
          );

        return (
          String(to).toLowerCase() ===
          String(expected).toLowerCase()
        );
      }
    );

  if (!transfer) {
    throw new Error(
      "Nenhum USDT foi enviado para a carteira da tesouraria."
    );
  }

  const rawText =
    String(
      transfer?.result?.value ??
      "0"
    );

  if (
    !/^\d+$/.test(
      rawText
    )
  ) {
    throw new Error(
      "Valor USDT on-chain inválido."
    );
  }

  const raw =
    BigInt(rawText);

  if (raw <= 0n) {
    throw new Error(
      "Valor USDT on-chain inválido."
    );
  }

  const amount =
    Number(raw) /
    USDT_FACTOR;

  if (
    !Number.isFinite(amount) ||
    amount <= 0
  ) {
    throw new Error(
      "Valor USDT inválido."
    );
  }

  const from =
    decodeTronAddress(
      transfer?.result?.from
    ) || null;

  const expectedAmount =
    Number(
      order.amount
    );

  if (
    Number.isFinite(
      expectedAmount
    ) &&
    expectedAmount > 0 &&
    Math.abs(
      amount -
        expectedAmount
    ) > 0.000001
  ) {
    throw new Error(
      "Quantidade USDT recebida diferente da quantidade esperada."
    );
  }

  const [
    saved
  ] =
    await sql`
      INSERT INTO blockchain_transactions(
        tx_hash,
        asset,
        amount,
        direction,
        address,
        confirmations,
        status
      )
      VALUES(
        ${order.tx_hash},
        'USDT',
        ${amount},
        'IN',
        ${expected},
        1,
        'CONFIRMED'
      )
      ON CONFLICT(tx_hash)
      DO UPDATE SET
        status='CONFIRMED',
        amount=EXCLUDED.amount
      RETURNING *
    `;

  return {
    ...saved,
    from
  };
}

async function confirmUSDTDeposit(
  order
) {
  const chain =
    await verifyUSDTDeposit(
      order
    );

  const amount =
    Number(
      chain.amount
    );

  /*
   * PRIMEIRO alteramos a wallet.
   *
   * A condição PENDING pertence ao
   * mesmo depósito e impede crédito
   * duplicado.
   */
  const [
    walletResult
  ] =
    await sql.transaction([
      sql`
        UPDATE treasury_wallet
        SET
          usdt=usdt+${amount},
          updated_at=NOW()
        WHERE
          id=1
          AND EXISTS (
            SELECT 1
            FROM treasury_deposits
            WHERE
              id=${order.id}
              AND status='PENDING'
          )
        RETURNING *
      `,

      sql`
        UPDATE treasury_deposits
        SET
          amount=${amount},
          currency='USDT',
          usdt_amount=${amount},
          status='COMPLETED',
          message='USDT confirmado na blockchain.',
          updated_at=NOW()
        WHERE
          id=${order.id}
          AND status='PENDING'
        RETURNING *
      `,

      sql`
        UPDATE transactions
        SET
          status='COMPLETED',
          tx_hash=${order.tx_hash}
        WHERE
          reference=${order.order_id}
          AND status='PENDING'
        RETURNING *
      `
    ]);

  if (
    !walletResult.length
  ) {
    const [
      current
    ] =
      await sql`
        SELECT *
        FROM treasury_deposits
        WHERE id=${order.id}
        LIMIT 1
      `;

    if (
      current?.status ===
      "COMPLETED"
    ) {
      return current;
    }

    throw new Error(
      "Falha ao creditar USDT na tesouraria."
    );
  }

  const [
    updated
  ] =
    await sql`
      SELECT *
      FROM treasury_deposits
      WHERE id=${order.id}
      LIMIT 1
    `;

  return updated || order;
}

/* =========================================================
   PAY CHARGE
========================================================= */

async function createPayDeposit(
  order
) {
  if (
    order.source !== "MPESA" &&
    order.source !== "EMOLA"
  ) {
    return {
      success: true,
      provider: false
    };
  }

  const method =
    payMethod(
      order.source
    );

  let contact =
    clean(
      order.payment_phone
    );

  contact =
    contact.replace(
      /\D/g,
      ""
    );

  if (
    /^\d{9}$/.test(
      contact
    )
  ) {
    contact =
      "258" + contact;
  }

  if (
    !/^258(84|85)\d{7}$/.test(
      contact
    )
  ) {
    throw new Error(
      "Número M-Pesa inválido. Use 84XXXXXXXX ou 85XXXXXXXX."
    );
  }

  const result =
    await pay(
      "/charges",
      {
        method: "POST",

        headers: {
          "Idempotency-Key":
            `usdtmz-${order.order_id}`
        },

        body:
          JSON.stringify({
            amount:
              round(
                Number(
                  order.amount
                ),
                2
              ),

            method,

            customer_name:
              "USDTMZ Admin",

            customer_contact:
              contact,

            wallet_id:
              Number(
                process.env.PAY_WALLET_ID
              )
          })
      }
    );

  const data =
    payData(result);

  const providerReference =
    extractPayReference(
      data
    );

  if (
    !providerReference
  ) {
    throw new Error(
      "PAY não devolveu a referência da cobrança."
    );
  }

  const providerId =
    clean(
      data?.id
    ) || null;

  const [
    updated
  ] =
    await sql`
      UPDATE treasury_deposits
      SET
        reference=${providerReference},
        provider_id=${providerId},
        message='Pagamento criado na PAY. Aguardando confirmação.',
        updated_at=NOW()
      WHERE
        id=${order.id}
      RETURNING *
    `;

  return {
    success: true,
    provider: true,
    provider_reference:
      providerReference,
    provider_id:
      providerId,
    status:
      data?.status ||
      data?.state ||
      "PENDING",
    checkout_url:
      data?.checkout_url ||
      null,
    order:
      updated || order
  };
}

/* =========================================================
   DEPOSIT STATUS
========================================================= */

async function depositStatus(
  orderId
) {
  if (!orderId) {
    throw new Error(
      "order_id obrigatório."
    );
  }

  const [
    order
  ] =
    await sql`
      SELECT *
      FROM treasury_deposits
      WHERE order_id=${orderId}
      LIMIT 1
    `;

  if (!order) {
    throw new Error(
      "Pedido não encontrado."
    );
  }

  if (
    order.status ===
    "COMPLETED"
  ) {
    return {
      success: true,
      confirmed: true,
      order
    };
  }

  if (
    order.source ===
    "USDT_TRON"
  ) {
    try {
      const updated =
        await confirmUSDTDeposit(
          order
        );

      return {
        success: true,
        confirmed: true,
        order: updated
      };
    } catch (e) {
      return {
        success: true,
        confirmed: false,
        status:
          order.status,
        message:
          e.message,
        order
      };
    }
  }

  return {
    success: true,
    confirmed: false,
    status:
      order.status,
    order
  };
}

/* =========================================================
   CONVERSÃO MZN -> USDT
========================================================= */

async function convertMZN(
  body
) {
  const amount =
    positive(
      body.amount_mzn ||
      body.amount
    );

  if (!amount) {
    throw new Error(
      "Valor MZN inválido."
    );
  }

  if (
    amount < MIN_MZN
  ) {
    throw new Error(
      `Valor mínimo: ${MIN_MZN} MZN.`
    );
  }

  if (
    amount > MAX_MZN
  ) {
    throw new Error(
      `Valor máximo: ${MAX_MZN} MZN.`
    );
  }

  const market =
    await marketFX();

  const usdt =
    calculateUSDT(
      amount,
      market.rate
    );

  if (
    !Number.isFinite(usdt) ||
    usdt <= 0
  ) {
    throw new Error(
      "Quantidade USDT inválida."
    );
  }

  const liquidity =
    await realLiquidity();

  if (
    liquidity.real_available_usdt <
    usdt
  ) {
    return {
      success: false,
      status:
        "INDISPONIVEL",
      reason:
        "LIQUIDEZ_USDT_INSUFICIENTE",
      requested_usdt:
        usdt,
      available_usdt:
        liquidity.real_available_usdt,
      rate:
        market.rate,
      rate_source:
        market.source,
      rate_timestamp:
        market.timestamp
    };
  }

  /*
   * Uma única transação.
   *
   * O UPDATE da wallet é o primeiro passo.
   * Os restantes só existem se a condição
   * da wallet tiver sido satisfeita.
   */
  const ref =
    reference("CONV");

  const [
    walletResult,
    conversionResult,
    reservationResult,
    transactionResult
  ] =
    await sql.transaction([

      sql`
        UPDATE treasury_wallet
        SET
          mzn=mzn-${amount},
          reserved_usdt=
            reserved_usdt+${usdt},
          updated_at=NOW()
        WHERE
          id=1
          AND mzn>=${amount}
          AND (
            usdt-reserved_usdt
          )>=${usdt}
        RETURNING *
      `,

      sql`
        INSERT INTO treasury_conversions(
          reference,
          mzn_amount,
          usdt_amount,
          rate,
          status
        )
        VALUES(
          ${ref},
          ${amount},
          ${usdt},
          ${market.rate},
          'COMPLETED'
        )
        RETURNING *
      `,

      sql`
        INSERT INTO treasury_reservations(
          reference,
          usdt_amount,
          status,
          reason
        )
        VALUES(
          ${ref},
          ${usdt},
          'RESERVED',
          'Conversão MZN -> USDT'
        )
        RETURNING *
      `,

      sql`
        INSERT INTO transactions(
          type,
          asset,
          amount,
          status,
          reference
        )
        VALUES(
          'CONVERSION_MZN_USDT',
          'USDT',
          ${usdt},
          'COMPLETED',
          ${ref}
        )
        RETURNING *
      `
    ]);

  if (
    !walletResult.length ||
    !conversionResult.length ||
    !reservationResult.length ||
    !transactionResult.length
  ) {
    throw new Error(
      "Saldo MZN ou liquidez USDT insuficiente para concluir a conversão."
    );
  }

  return {
    success: true,
    status:
      "COMPLETED",
    reference:
      ref,
    mzn:
      amount,
    usdt,
    rate:
      market.rate,
    rate_source:
      market.source,
    rate_timestamp:
      market.timestamp,
    note:
      "USDT proveniente de liquidez real da tesouraria."
  };
}

/* =========================================================
   RESERVA USDT
========================================================= */

async function reserveUSDT(
  body
) {
  const amount =
    positive(
      body.amount_usdt ||
      body.amount
    );

  if (!amount) {
    throw new Error(
      "Valor USDT inválido."
    );
  }

  const reason =
    clean(
      body.reason
    ) ||
    "Reserva administrativa";

  const ref =
    reference("RES");

  const [
    walletResult
  ] =
    await sql.transaction([

      sql`
        UPDATE treasury_wallet
        SET
          reserved_usdt=
            reserved_usdt+${amount},
          updated_at=NOW()
        WHERE
          id=1
          AND (
            usdt-reserved_usdt
          )>=${amount}
        RETURNING *
      `,

      sql`
        INSERT INTO treasury_reservations(
          reference,
          usdt_amount,
          status,
          reason
        )
        VALUES(
          ${ref},
          ${amount},
          'RESERVED',
          ${reason}
        )
        RETURNING *
      `
    ]);

  if (
    !walletResult.length
  ) {
    throw new Error(
      "USDT disponível insuficiente."
    );
  }

  return {
    success: true,
    reference:
      ref,
    amount_usdt:
      amount,
    status:
      "RESERVED"
  };
}

/* =========================================================
   RELEASE RESERVATION
========================================================= */

async function releaseReservation(
  body
) {
  const ref =
    clean(
      body.reference ||
      body.reservation_reference
    );

  if (!ref) {
    throw new Error(
      "Referência da reserva obrigatória."
    );
  }

  /*
   * Primeiro capturamos a reserva.
   * Depois alteramos wallet dentro da
   * mesma transação.
   */
  const [
    reservation
  ] =
    await sql`
      SELECT *
      FROM treasury_reservations
      WHERE
        reference=${ref}
        AND status='RESERVED'
      LIMIT 1
    `;

  if (!reservation) {
    return {
      success: true,
      already_processed: true,
      reference:
        ref
    };
  }

  const amount =
    Number(
      reservation.usdt_amount
    );

  const [
    changedResult,
    walletResult
  ] =
    await sql.transaction([

      sql`
        UPDATE treasury_reservations
        SET
          status='RELEASED'
        WHERE
          reference=${ref}
          AND status='RESERVED'
        RETURNING *
      `,

      sql`
        UPDATE treasury_wallet
        SET
          reserved_usdt=
            GREATEST(
              0,
              reserved_usdt-${amount}
            ),
          updated_at=NOW()
        WHERE
          id=1
          AND reserved_usdt>=${amount}
        RETURNING *
      `
    ]);

  if (
    !changedResult.length
  ) {
    return {
      success: true,
      already_processed: true,
      reference:
        ref
    };
  }

  if (
    !walletResult.length
  ) {
    throw new Error(
      "Não foi possível liberar a reserva USDT."
    );
  }

  return {
    success: true,
    reference:
      ref,
    amount_usdt:
      amount,
    status:
      "RELEASED"
  };
}

/* =========================================================
   CRIAR RETIRADA
========================================================= */

async function createWithdrawal(
  body
) {
  const method =
    upper(
      body.method ||
      "MPESA"
    );

  if (
    method !== "MPESA"
  ) {
    throw new Error(
      "A retirada automática atualmente implementada pela PAY é M-Pesa."
    );
  }

  const amount =
    positive(
      body.amount_mzn ||
      body.amount
    );

  if (!amount) {
    throw new Error(
      "Valor de retirada inválido."
    );
  }

  if (!payConfigured()) {
    throw new Error(
      "PAY.co.mz não está configurado."
    );
  }

  const destination =
    clean(
      process.env.PAY_PAYOUT_DESTINATION
    ) || null;

  const ref =
    reference("WD");

  const [
    reservedResult,
    withdrawalResult
  ] =
    await sql.transaction([

      sql`
        UPDATE treasury_wallet
        SET
          reserved_mzn=
            reserved_mzn+${amount},
          updated_at=NOW()
        WHERE
          id=1
          AND (
            mzn-reserved_mzn
          )>=${amount}
        RETURNING *
      `,

      sql`
        INSERT INTO treasury_withdrawals(
          reference,
          method,
          amount,
          currency,
          destination,
          status,
          approval_status,
          provider,
          message
        )
        VALUES(
          ${ref},
          'MPESA',
          ${amount},
          'MZN',
          ${destination},
          'PENDING',
          'PENDING',
          'PAY',
          'Retirada criada e aguardando aprovação administrativa.'
        )
        RETURNING *
      `
    ]);

  if (
    !reservedResult.length ||
    !withdrawalResult.length
  ) {
    throw new Error(
      "Saldo MZN disponível insuficiente."
    );
  }

  return {
    success: true,
    status:
      "PENDING",
    approval_status:
      "PENDING",
    reference:
      ref,
    amount_mzn:
      amount,
    method:
      "MPESA",
    provider:
      "PAY",
    message:
      "Retirada criada. Nenhum payout foi enviado.",
    withdrawal:
      withdrawalResult[0]
  };
}

/* =========================================================
   APROVAR RETIRADA
========================================================= */

async function approveWithdrawal(
  body
) {
  const ref =
    clean(
      body.reference ||
      body.withdrawal_reference
    );

  if (!ref) {
    throw new Error(
      "Referência da retirada obrigatória."
    );
  }

  const [
    row
  ] =
    await sql`
      UPDATE treasury_withdrawals
      SET
        approval_status='APPROVED',
        message='Retirada aprovada pelo administrador. Aguardando processamento.',
        updated_at=NOW()
      WHERE
        reference=${ref}
        AND status='PENDING'
        AND approval_status='PENDING'
      RETURNING *
    `;

  if (!row) {
    const [
      current
    ] =
      await sql`
        SELECT *
        FROM treasury_withdrawals
        WHERE reference=${ref}
        LIMIT 1
      `;

    if (
      current?.approval_status ===
      "APPROVED"
    ) {
      return {
        success: true,
        already_approved:
          true,
        withdrawal:
          current
      };
    }

    throw new Error(
      "A retirada não está PENDING."
    );
  }

  return {
    success: true,
    status:
      row.status,
    approval_status:
      row.approval_status,
    reference:
      ref,
    message:
      "Retirada APPROVED. Ainda não foi enviada à PAY.",
    withdrawal:
      row
  };
}

/* =========================================================
   PROCESSAR RETIRADA
========================================================= */

async function processWithdrawal(
  body
) {
  const ref =
    clean(
      body.reference ||
      body.withdrawal_reference
    );

  if (!ref) {
    throw new Error(
      "Referência da retirada obrigatória."
    );
  }

  const [
    withdrawal
  ] =
    await sql`
      UPDATE treasury_withdrawals
      SET
        status='PROCESSING',
        message='Retirada aprovada e em processamento na PAY.',
        updated_at=NOW()
      WHERE
        reference=${ref}
        AND approval_status='APPROVED'
        AND status='PENDING'
      RETURNING *
    `;

  if (!withdrawal) {
    const [
      current
    ] =
      await sql`
        SELECT *
        FROM treasury_withdrawals
        WHERE reference=${ref}
        LIMIT 1
      `;

    if (!current) {
      throw new Error(
        "Retirada não encontrada."
      );
    }

    if (
      current.status ===
      "COMPLETED"
    ) {
      return {
        success: true,
        already_completed:
          true,
        withdrawal:
          current
      };
    }

    if (
      current.status ===
      "PROCESSING"
    ) {
      return {
        success: true,
        already_processing:
          true,
        withdrawal:
          current
      };
    }

    throw new Error(
      "A retirada precisa estar APPROVED antes do processamento."
    );
  }

  const amount =
    Number(
      withdrawal.amount
    );

  try {
    const result =
      await pay(
        "/payouts",
        {
          method:
            "POST",

          body:
            JSON.stringify({
              amount:
                round(
                  amount,
                  2
                )
            })
        }
      );

    const data =
      payData(result);

    const providerId =
      clean(
        data?.id
      ) || null;

    const providerReference =
      clean(
        data?.reference ||
        data?.transaction_reference
      ) || null;

    const providerStatus =
      upper(
        data?.status ||
        data?.state ||
        "PROCESSING"
      );

    const providerFee =
      positive(
        data?.fee
      ) || 0;

    const providerNet =
      positive(
        data?.net
      ) ||
      positive(
        data?.net_amount
      ) ||
      amount;

    const completed =
      [
        "PAID",
        "SUCCESS",
        "SUCCEEDED",
        "COMPLETED",
        "SUCCESSFUL"
      ].includes(
        providerStatus
      );

    const storedReference =
      providerReference ||
      providerId ||
      null;

    if (
      !storedReference
    ) {
      throw new Error(
        "PAY não devolveu identificador do payout."
      );
    }

    if (completed) {

      const [
        walletResult
      ] =
        await sql.transaction([

          sql`
            UPDATE treasury_wallet
            SET
              reserved_mzn=
                GREATEST(
                  0,
                  reserved_mzn-${amount}
                ),
              mzn=
                GREATEST(
                  0,
                  mzn-${amount}
                ),
              updated_at=NOW()
            WHERE
              id=1
              AND reserved_mzn>=${amount}
              AND EXISTS (
                SELECT 1
                FROM treasury_withdrawals
                WHERE
                  id=${withdrawal.id}
                  AND status='PROCESSING'
              )
            RETURNING *
          `,

          sql`
            UPDATE treasury_withdrawals
            SET
              provider='PAY',
              provider_reference=${storedReference},
              provider_id=${providerId},
              fee=${providerFee},
              net_amount=${providerNet},
              status='COMPLETED',
              message='Payout confirmado pela PAY.',
              updated_at=NOW()
            WHERE
              id=${withdrawal.id}
              AND status='PROCESSING'
            RETURNING *
          `,

          sql`
            INSERT INTO transactions(
              type,
              asset,
              amount,
              status,
              reference,
              provider,
              provider_reference
            )
            VALUES(
              'WITHDRAWAL_MZN_MPESA',
              'MZN',
              ${amount},
              'COMPLETED',
              ${ref},
              'PAY',
              ${storedReference}
            )
            ON CONFLICT(reference)
            DO NOTHING
            RETURNING *
          `
        ]);

      if (
        !walletResult.length
      ) {
        throw new Error(
          "Não foi possível finalizar contabilmente o payout."
        );
      }

      const [
        updated
      ] =
        await sql`
          SELECT *
          FROM treasury_withdrawals
          WHERE id=${withdrawal.id}
        `;

      return {
        success: true,
        status:
          "COMPLETED",
        approval_status:
          "APPROVED",
        reference:
          ref,
        provider:
          "PAY",
        provider_reference:
          storedReference,
        provider_id:
          providerId,
        payout:
          result,
        withdrawal:
          updated?.[0] ||
          withdrawal
      };
    }

    const [
      updated
    ] =
      await sql`
        UPDATE treasury_withdrawals
        SET
          provider='PAY',
          provider_reference=${storedReference},
          provider_id=${providerId},
          fee=${providerFee},
          net_amount=${providerNet},
          status='PROCESSING',
          message='Payout submetido à PAY; aguardando confirmação.',
          updated_at=NOW()
        WHERE
          id=${withdrawal.id}
          AND status='PROCESSING'
        RETURNING *
      `;

    return {
      success: true,
      status:
        "PROCESSING",
      approval_status:
        "APPROVED",
      reference:
        ref,
      provider:
        "PAY",
      provider_reference:
        storedReference,
      provider_id:
        providerId,
      payout:
        result,
      withdrawal:
        updated?.[0] ||
        withdrawal
    };

  } catch (e) {

    /*
     * Timeout, erro de rede ou 5xx:
     * estado externo desconhecido.
     *
     * NÃO liberamos a reserva.
     * NÃO reenviamos automaticamente.
     */
    if (
      e?.code ===
      "UPSTREAM_TIMEOUT" ||
      e?.statusCode >= 500
    ) {

      await sql`
        UPDATE treasury_withdrawals
        SET
          status='PROCESSING',
          message='Estado do payout desconhecido. Aguardando reconciliação PAY.',
          updated_at=NOW()
        WHERE
          id=${withdrawal.id}
          AND status='PROCESSING'
      `;

      return {
        success: true,
        status:
          "PROCESSING",
        uncertain:
          true,
        reference:
          ref,
        message:
          "A resposta da PAY não pôde ser confirmada. Nenhum novo payout será enviado automaticamente."
      };
    }

    await sql`
      UPDATE treasury_withdrawals
      SET
        status='FAILED',
        message=${e.message},
        updated_at=NOW()
      WHERE
        id=${withdrawal.id}
        AND status='PROCESSING'
    `;

    throw e;
  }
}

/* =========================================================
   CANCELAR PENDING
========================================================= */

async function cancelWithdrawal(
  body
) {
  const ref =
    clean(
      body.reference ||
      body.withdrawal_reference
    );

  if (!ref) {
    throw new Error(
      "Referência obrigatória."
    );
  }

  const [
    row
  ] =
    await sql`
      UPDATE treasury_withdrawals
      SET
        status='CANCELLED',
        approval_status='REJECTED',
        message='Retirada cancelada pelo administrador.',
        updated_at=NOW()
      WHERE
        reference=${ref}
        AND status='PENDING'
        AND approval_status='PENDING'
      RETURNING *
    `;

  if (!row) {
    throw new Error(
      "A retirada não está PENDING."
    );
  }

  const amount =
    Number(
      row.amount
    );

  const [
    wallet
  ] =
    await sql`
      UPDATE treasury_wallet
      SET
        reserved_mzn=
          GREATEST(
            0,
            reserved_mzn-${amount}
          ),
        updated_at=NOW()
      WHERE
        id=1
        AND reserved_mzn>=${amount}
      RETURNING *
    `;

  if (!wallet) {
    throw new Error(
      "Não foi possível liberar a reserva MZN."
    );
  }

  return {
    success: true,
    status:
      "CANCELLED",
    reference:
      ref
  };
}

/* =========================================================
   LIBERAR RESERVA DE RETIRADA FALHADA
========================================================= */

async function releaseFailedWithdrawal(
  body
) {
  const ref =
    clean(
      body.reference ||
      body.withdrawal_reference
    );

  if (!ref) {
    throw new Error(
      "Referência obrigatória."
    );
  }

  const [
    current
  ] =
    await sql`
      SELECT *
      FROM treasury_withdrawals
      WHERE reference=${ref}
      LIMIT 1
    `;

  if (!current) {
    throw new Error(
      "Retirada não encontrada."
    );
  }

  if (
    current.status ===
    "CANCELLED"
  ) {
    return {
      success: true,
      already_processed:
        true,
      reference:
        ref
    };
  }

  if (
    current.status !==
    "FAILED"
  ) {
    throw new Error(
      "Somente uma retirada FAILED pode ter a reserva liberada."
    );
  }

  const amount =
    Number(
      current.amount
    );

  const [
    row
  ] =
    await sql.transaction([

      sql`
        UPDATE treasury_wallet
        SET
          reserved_mzn=
            GREATEST(
              0,
              reserved_mzn-${amount}
            ),
          updated_at=NOW()
        WHERE
          id=1
          AND reserved_mzn>=${amount}
        RETURNING *
      `,

      sql`
        UPDATE treasury_withdrawals
        SET
          status='CANCELLED',
          message='Reserva liberada após falha confirmada do payout.',
          updated_at=NOW()
        WHERE
          reference=${ref}
          AND status='FAILED'
        RETURNING *
      `
    ]);

  if (
    !row?.length
  ) {
    throw new Error(
      "Não foi possível liberar a reserva da retirada."
    );
  }

  return {
    success: true,
    status:
      "CANCELLED",
    reference:
      ref
  };
}

/* =========================================================
   RETIRADAS
========================================================= */

async function withdrawals() {
  const rows =
    await sql`
      SELECT *
      FROM treasury_withdrawals
      ORDER BY id DESC
      LIMIT 100
    `;

  return {
    success: true,
    withdrawals:
      rows
  };
}

/* =========================================================
   DASHBOARD
========================================================= */

async function dashboard() {
  const wallet =
    await treasury();

  const liquidity =
    await realLiquidity();

  let market;

  try {
    market =
      await marketFX();
  } catch {
    market = {
      rate: null,
      source:
        "UNAVAILABLE",
      timestamp: null
    };
  }

  const [
    pending
  ] =
    await sql`
      SELECT COUNT(*)::int AS count
      FROM treasury_deposits
      WHERE status='PENDING'
    `;

  const [
    pendingWithdrawals
  ] =
    await sql`
      SELECT COUNT(*)::int AS count
      FROM treasury_withdrawals
      WHERE
        status='PENDING'
        AND approval_status='PENDING'
    `;

  return {
    success: true,

    treasury: {
      mzn:
        wallet.mzn,

      usdt:
        wallet.usdt,

      trx:
        wallet.trx,

      reserved_usdt:
        wallet.reserved_usdt,

      reserved_mzn:
        wallet.reserved_mzn,

      available_usdt:
        Math.max(
          0,
          wallet.usdt -
            wallet.reserved_usdt
        ),

      available_mzn:
        Math.max(
          0,
          wallet.mzn -
            wallet.reserved_mzn
        )
    },

    liquidity,

    fx: {
      mzn_usdt:
        market.rate,

      source:
        market.source,

      timestamp:
        market.timestamp
    },

    pending_deposits:
      Number(
        pending?.count || 0
      ),

    pending_withdrawals:
      Number(
        pendingWithdrawals?.count || 0
      ),

    status:
      liquidity.real_available_usdt > 0
        ? "LIQUIDEZ_DISPONIVEL"
        : "SEM_LIQUIDEZ"
  };
}

/* =========================================================
   OPERATIONS
========================================================= */

async function operations() {
  const deposits =
    await sql`
      SELECT *
      FROM treasury_deposits
      ORDER BY id DESC
      LIMIT 100
    `;

  const conversions =
    await sql`
      SELECT *
      FROM treasury_conversions
      ORDER BY id DESC
      LIMIT 100
    `;

  const withdrawalRows =
    await sql`
      SELECT *
      FROM treasury_withdrawals
      ORDER BY id DESC
      LIMIT 100
    `;

  return {
    success: true,
    deposits,
    conversions,
    withdrawals:
      withdrawalRows
  };
}

/* =========================================================
   SOURCES
========================================================= */

async function sources() {
  return {
    success: true,

    deposit_methods:
      DEPOSIT_SOURCES,

    liquidity_sources:
      LIQUIDITY_SOURCES,

    pay: {
      configured:
        payConfigured(),

      wallet_id:
        process.env.PAY_WALLET_ID
          ? String(
              process.env.PAY_WALLET_ID
            )
          : null,

      payout_destination_configured:
        Boolean(
          process.env.PAY_PAYOUT_DESTINATION
        ),

      mpesa_production:
        true,

      emola_production:
        false
    },

    fx: {
      source:
        "COINGECKO_MARKET",

      url_configured:
        Boolean(
          FX_MARKET_URL
        )
    },

    tron: {
      configured:
        Boolean(
          process.env.TRON_PRO_API_KEY
        ),

      contract:
        CONTRACT,

      treasury:
        (() => {
          try {
            return treasuryAddress();
          } catch {
            return null;
          }
        })()
    }
  };
}

/* =========================================================
   CONFIG
========================================================= */

async function configStatus() {
  let market;

  try {
    market =
      await marketFX();
  } catch {
    market = {
      rate: null,
      source:
        "UNAVAILABLE",
      timestamp: null
    };
  }

  return {
    success: true,

    currency:
      "MZN",

    asset:
      "USDT",

    network:
      "TRON/TRC20",

    min_mzn:
      MIN_MZN,

    max_mzn:
      MAX_MZN,

    rate:
      market.rate,

    rate_source:
      market.source,

    rate_timestamp:
      market.timestamp,

    contract:
      CONTRACT,

    pay_configured:
      payConfigured(),

    pay_payout_destination_configured:
      Boolean(
        process.env.PAY_PAYOUT_DESTINATION
      ),

    deposit_methods:
      [
        "MPESA",
        "BANK",
        "USDT_TRON",
        "EXTERNAL",
        "MANUAL"
      ],

    withdrawal_methods:
      [
        "MPESA"
      ],

    mpesa_production:
      true,

    emola_production:
      false
  };
}

/* =========================================================
   PAY WEBHOOK
========================================================= */

function parsePaySignature(
  value
) {
  const out = {};

  for (
    const part of String(
      value || ""
    ).split(",")
  ) {
    const [
      key,
      ...rest
    ] =
      part.split("=");

    if (key) {
      out[
        key.trim()
      ] =
        rest
          .join("=")
          .trim();
    }
  }

  if (
    out.t &&
    out.v1
  ) {
    return {
      timestamp:
        out.t,

      signature:
        out.v1
    };
  }

  return null;
}

/*
 * Verifica se o evento já foi processado.
 */
async function webhookAlreadyProcessed(
  eventId
) {
  const [
    row
  ] =
    await sql`
      SELECT event_id
      FROM pay_webhook_events
      WHERE event_id=${eventId}
      LIMIT 1
    `;

  return Boolean(row);
}

/*
 * Registra somente depois de o evento
 * ter sido processado com sucesso ou
 * considerado definitivamente ignorado.
 *
 * Se ocorrer erro temporário antes disso,
 * não gravamos o event_id, permitindo
 * que a PAY faça retry.
 */
async function markWebhookProcessed(
  eventId,
  eventName
) {
  await sql`
    INSERT INTO pay_webhook_events(
      event_id,
      event_name
    )
    VALUES(
      ${eventId},
      ${eventName}
    )
    ON CONFLICT(event_id)
    DO NOTHING
  `;
}

async function payWebhook(
  req,
  res
) {
  const secret =
    process.env.PAY_WEBHOOK_SECRET;

  if (!secret) {
    return json(
      res,
      500,
      {
        success: false,
        error:
          "PAY_WEBHOOK_SECRET não configurado."
      }
    );
  }

  const raw =
    await requestRawBody(
      req
    );

  const parsed =
    parsePaySignature(
      req.headers[
        "x-pay-signature"
      ]
    );

  if (!parsed) {
    return json(
      res,
      401,
      {
        success: false,
        error:
          "Assinatura Pay ausente."
      }
    );
  }

  const timestamp =
    Number(
      parsed.timestamp
    );

  const milliseconds =
    timestamp < 1e10
      ? timestamp * 1000
      : timestamp;

  if (
    !Number.isFinite(
      timestamp
    ) ||
    Math.abs(
      Date.now() -
        milliseconds
    ) > 300000
  ) {
    return json(
      res,
      401,
      {
        success: false,
        error:
          "Webhook expirado."
      }
    );
  }

  const expected =
    createHmac(
      "sha256",
      secret
    )
      .update(
        `${parsed.timestamp}.${raw}`
      )
      .digest("hex");

  if (
    !safeEqual(
      parsed.signature,
      expected
    )
  ) {
    return json(
      res,
      401,
      {
        success: false,
        error:
          "Assinatura inválida."
      }
    );
  }

  let event;

  try {
    event =
      JSON.parse(raw);
  } catch {
    return json(
      res,
      400,
      {
        success: false,
        error:
          "JSON inválido."
      }
    );
  }

  const eventName =
    clean(
      req.headers[
        "x-pay-event"
      ] ||
      event?.event
    );

  const eventId =
    clean(
      req.headers[
        "x-pay-event-id"
      ] ||
      event?.id ||
      event?.event_id
    );

  if (!eventId) {
    return json(
      res,
      400,
      {
        success: false,
        error:
          "X-Pay-Event-Id ausente."
      }
    );
  }

  /*
   * Se já foi concluído, não processamos
   * novamente.
   */
  if (
    await webhookAlreadyProcessed(
      eventId
    )
  ) {
    return json(
      res,
      200,
      {
        success: true,
        duplicate: true,
        event:
          eventName
      }
    );
  }

  const data =
    event?.data ||
    event?.payment ||
    event?.payout ||
    event?.charge ||
    event;

  /* =======================================================
     PAYMENT SUCCEEDED
  ======================================================= */

  if (
    eventName ===
    "payment.succeeded"
  ) {
    const providerReference =
      extractPayReference(
        data
      );

    if (
      !providerReference
    ) {
      await markWebhookProcessed(
        eventId,
        eventName
      );

      return json(
        res,
        200,
        {
          success: true,
          ignored: true,
          reason:
            "Sem referência PAY."
        }
      );
    }

    const [
      order
    ] =
      await sql`
        SELECT *
        FROM treasury_deposits
        WHERE reference=${providerReference}
        LIMIT 1
      `;

    if (!order) {
      await markWebhookProcessed(
        eventId,
        eventName
      );

      return json(
        res,
        200,
        {
          success: true,
          ignored: true,
          reason:
            "Referência PAY não associada ao USDTMZ."
        }
      );
    }

    /*
     * Se já estiver concluído, apenas
     * marcamos o webhook como processado.
     */
    if (
      order.status ===
      "COMPLETED"
    ) {
      await markWebhookProcessed(
        eventId,
        eventName
      );

      return json(
        res,
        200,
        {
          success: true,
          already_completed:
            true,
          order_id:
            order.order_id
        }
      );
    }

    const providerAmount =
      Number(
        data?.amount
      );

    const orderAmount =
      Number(
        order.amount
      );

    if (
      Number.isFinite(
        providerAmount
      ) &&
      providerAmount > 0 &&
      Math.abs(
        providerAmount -
          orderAmount
      ) > 0.01
    ) {
      /*
       * Não marcamos como processado.
       * É uma inconsistência que precisa
       * ser tratada/reconciliada.
       */
      return json(
        res,
        400,
        {
          success: false,
          error:
            "Valor do pagamento PAY diferente do valor da ordem."
        }
      );
    }

    const method =
      clean(
        data?.method ||
        data?.provider ||
        ""
      ).toLowerCase();

    if (
      method &&
      method !== "mpesa"
    ) {
      return json(
        res,
        400,
        {
          success: false,
          error:
            "Método PAY inesperado para esta cobrança."
        }
      );
    }

    /*
     * Reconciliação com GET /charges.
     */
    let charge;

    try {
      charge =
        await findPayCharge(
          providerReference
        );
    } catch (e) {
      /*
       * NÃO marcamos event_id.
       * A PAY poderá reenviar.
       */
      return json(
        res,
        503,
        {
          success: false,
          error:
            "Não foi possível reconciliar a cobrança PAY.",
          retry: true
        }
      );
    }

    if (!charge) {
      return json(
        res,
        503,
        {
          success: false,
          error:
            "Cobrança PAY não encontrada na reconciliação.",
          retry: true
        }
      );
    }

    const chargeAmount =
      Number(
        charge.amount
      );

    if (
      !Number.isFinite(
        chargeAmount
      ) ||
      Math.abs(
        chargeAmount -
          orderAmount
      ) > 0.01
    ) {
      return json(
        res,
        400,
        {
          success: false,
          error:
            "Valor reconciliado pela PAY não corresponde à ordem."
        }
      );
    }

    const fee =
      Number(
        charge.fee
      );

    const net =
      Number(
        charge.net ??
        charge.net_amount
      );

    if (
      !Number.isFinite(fee) ||
      !Number.isFinite(net) ||
      fee < 0 ||
      net <= 0
    ) {
      return json(
        res,
        503,
        {
          success: false,
          error:
            "PAY não devolveu fee/net válidos.",
          retry: true
        }
      );
    }

    const state =
      upper(
        charge?.status ||
        data?.state ||
        data?.status ||
        "SUCCESSFUL"
      );

    if (
      [
        "FAILED",
        "CANCELLED",
        "EXPIRED",
        "REVERSED"
      ].includes(
        state
      )
    ) {
      await sql`
        UPDATE treasury_deposits
        SET
          status='FAILED',
          fee=${fee},
          net_amount=${net},
          message='Pagamento não foi concluído na PAY.',
          updated_at=NOW()
        WHERE
          id=${order.id}
          AND status='PENDING'
      `;

      await sql`
        UPDATE transactions
        SET
          status='FAILED',
          provider='PAY',
          provider_reference=${providerReference}
        WHERE
          reference=${order.order_id}
          AND status='PENDING'
      `;

      await markWebhookProcessed(
        eventId,
        eventName
      );

      return json(
        res,
        200,
        {
          success: true,
          event:
            eventName,
          status:
            "FAILED"
        }
      );
    }

    const providerId =
      clean(
        charge?.id ||
        data?.id
      ) || null;

    /*
     * CRÍTICO:
     *
     * A wallet é atualizada ANTES do
     * depósito mudar de PENDING.
     *
     * Assim a condição PENDING continua
     * válida durante a transação.
     *
     * Se qualquer query falhar,
     * toda a transação sofre rollback.
     */
    const [
      walletResult,
      changedResult,
      transactionResult
    ] =
      await sql.transaction([

        sql`
          UPDATE treasury_wallet
          SET
            mzn=mzn+${net},
            updated_at=NOW()
          WHERE
            id=1
            AND EXISTS (
              SELECT 1
              FROM treasury_deposits
              WHERE
                id=${order.id}
                AND status='PENDING'
            )
          RETURNING *
        `,

        sql`
          UPDATE treasury_deposits
          SET
            status='COMPLETED',
            fee=${fee},
            net_amount=${net},
            provider_id=${providerId},
            message='Pagamento confirmado pela PAY; valor líquido creditado.',
            updated_at=NOW()
          WHERE
            id=${order.id}
            AND status='PENDING'
          RETURNING *
        `,

        sql`
          UPDATE transactions
          SET
            status='COMPLETED',
            provider='PAY',
            provider_reference=${providerReference}
          WHERE
            reference=${order.order_id}
            AND status='PENDING'
          RETURNING *
        `
      ]);

    /*
     * Se outra tentativa já tiver concluído
     * o depósito, não creditamos novamente.
     */
    if (
      !walletResult.length
    ) {
      const [
        current
      ] =
        await sql`
          SELECT *
          FROM treasury_deposits
          WHERE id=${order.id}
          LIMIT 1
        `;

      if (
        current?.status ===
        "COMPLETED"
      ) {
        await markWebhookProcessed(
          eventId,
          eventName
        );

        return json(
          res,
          200,
          {
            success: true,
            already_completed:
              true,
            order_id:
              order.order_id
          }
        );
      }

      throw new Error(
        "Falha ao creditar saldo líquido PAY."
      );
    }

    if (
      !changedResult.length
    ) {
      throw new Error(
        "Depósito não pôde ser marcado como COMPLETED."
      );
    }

    /*
     * transactions pode não existir em bases
     * antigas para esta referência.
     * O depósito e a wallet são a fonte
     * financeira principal.
     */

    await markWebhookProcessed(
      eventId,
      eventName
    );

    return json(
      res,
      200,
      {
        success: true,
        event:
          eventName,
        order_id:
          order.order_id,
        gross:
          chargeAmount,
        fee,
        net,
        status:
          "COMPLETED"
      }
    );
  }

  /* =======================================================
     PAYMENT FAILED
  ======================================================= */

  if (
    eventName ===
    "payment.failed"
  ) {
    const providerReference =
      extractPayReference(
        data
      );

    if (
      providerReference
    ) {
      await sql`
        UPDATE treasury_deposits
        SET
          status='FAILED',
          message='Pagamento recusado/cancelado/expirado pela PAY.',
          updated_at=NOW()
        WHERE
          reference=${providerReference}
          AND status='PENDING'
      `;

      await sql`
        UPDATE transactions
        SET
          status='FAILED',
          provider='PAY',
          provider_reference=${providerReference}
        WHERE
          reference=(
            SELECT order_id
            FROM treasury_deposits
            WHERE reference=${providerReference}
            LIMIT 1
          )
          AND status='PENDING'
      `;
    }

    await markWebhookProcessed(
      eventId,
      eventName
    );

    return json(
      res,
      200,
      {
        success: true,
        event:
          eventName,
        status:
          "FAILED"
      }
    );
  }

  /* =======================================================
     PAYOUT PAID
  ======================================================= */

  if (
    eventName ===
    "payout.paid"
  ) {
    const providerId =
      clean(
        data?.id
      );

    const providerReference =
      clean(
        data?.reference ||
        data?.transaction_reference ||
        data?.payout_reference
      );

    const [
      withdrawal
    ] =
      await sql`
        SELECT *
        FROM treasury_withdrawals
        WHERE
          (
            provider_id=${providerId}
            AND ${providerId} <> ''
          )
          OR
          (
            provider_reference=${providerReference}
            AND ${providerReference} <> ''
          )
        ORDER BY id DESC
        LIMIT 1
      `;

    if (!withdrawal) {
      await markWebhookProcessed(
        eventId,
        eventName
      );

      return json(
        res,
        200,
        {
          success: true,
          ignored: true
        }
      );
    }

    /*
     * Já COMPLETED:
     * nunca descontar novamente.
     */
    if (
      withdrawal.status ===
      "COMPLETED"
    ) {
      await markWebhookProcessed(
        eventId,
        eventName
      );

      return json(
        res,
        200,
        {
          success: true,
          already_completed:
            true
        }
      );
    }

    const amount =
      Number(
        withdrawal.amount
      );

    const fee =
      Number(
        data?.fee || 0
      );

    const net =
      Number(
        data?.net ??
        data?.net_amount ??
        amount
      );

    /*
     * PRIMEIRO reduzimos a reserva.
     * A condição PROCESSING/FAILED impede
     * dupla liquidação.
     */
    const [
      walletResult,
      changedResult,
      transactionResult
    ] =
      await sql.transaction([

        sql`
          UPDATE treasury_wallet
          SET
            reserved_mzn=
              reserved_mzn-${amount},
            mzn=
              mzn-${amount},
            updated_at=NOW()
          WHERE
            id=1
            AND reserved_mzn>=${amount}
            AND EXISTS (
              SELECT 1
              FROM treasury_withdrawals
              WHERE
                id=${withdrawal.id}
                AND status <> 'COMPLETED'
            )
          RETURNING *
        `,

        sql`
          UPDATE treasury_withdrawals
          SET
            status='COMPLETED',
            approval_status='APPROVED',
            provider='PAY',
            provider_id=${
              providerId || null
            },
            provider_reference=${
              providerReference ||
              providerId ||
              null
            },
            fee=${fee},
            net_amount=${net},
            message='Payout M-Pesa confirmado pela PAY.',
            updated_at=NOW()
          WHERE
            id=${withdrawal.id}
            AND status <> 'COMPLETED'
          RETURNING *
        `,

        sql`
          INSERT INTO transactions(
            type,
            asset,
            amount,
            status,
            reference,
            provider,
            provider_reference
          )
          VALUES(
            'WITHDRAWAL_MZN_MPESA',
            'MZN',
            ${amount},
            'COMPLETED',
            ${withdrawal.reference},
            'PAY',
            ${
              providerReference ||
              providerId ||
              null
            }
          )
          ON CONFLICT(reference)
          DO NOTHING
          RETURNING *
        `
      ]);

    if (
      !walletResult.length
    ) {
      throw new Error(
        "Reserva MZN insuficiente para liquidar payout confirmado."
      );
    }

    await markWebhookProcessed(
      eventId,
      eventName
    );

    return json(
      res,
      200,
      {
        success: true,
        event:
          eventName,
        status:
          "COMPLETED"
      }
    );
  }

  /* =======================================================
     PAYOUT FAILED
  ======================================================= */

  if (
    eventName ===
    "payout.failed"
  ) {
    const providerId =
      clean(
        data?.id
      );

    const providerReference =
      clean(
        data?.reference ||
        data?.transaction_reference ||
        data?.payout_reference
      );

    const [
      withdrawal
    ] =
      await sql`
        SELECT *
        FROM treasury_withdrawals
        WHERE
          (
            provider_id=${providerId}
            AND ${providerId} <> ''
          )
          OR
          (
            provider_reference=${providerReference}
            AND ${providerReference} <> ''
          )
        ORDER BY id DESC
        LIMIT 1
      `;

    if (!withdrawal) {
      await markWebhookProcessed(
        eventId,
        eventName
      );

      return json(
        res,
        200,
        {
          success: true,
          ignored: true
        }
      );
    }

    if (
      withdrawal.status ===
      "COMPLETED"
    ) {
      await markWebhookProcessed(
        eventId,
        eventName
      );

      return json(
        res,
        200,
        {
          success: true,
          already_completed:
            true
        }
      );
    }

    await sql`
      UPDATE treasury_withdrawals
      SET
        status='FAILED',
        provider='PAY',
        provider_id=${
          providerId || null
        },
        provider_reference=${
          providerReference ||
          null
        },
        message='Payout recusado/falhado pela PAY. Reserva ainda mantida até liberação administrativa.',
        updated_at=NOW()
      WHERE
        id=${withdrawal.id}
        AND status <> 'COMPLETED'
        AND status <> 'FAILED'
    `;

    /*
     * NÃO liberamos a reserva automaticamente.
     */
    await markWebhookProcessed(
      eventId,
      eventName
    );

    return json(
      res,
      200,
      {
        success: true,
        event:
          eventName,
        status:
          "FAILED"
      }
    );
  }

  /* =======================================================
     EVENTO DESCONHECIDO
  ======================================================= */

  await markWebhookProcessed(
    eventId,
    eventName
  );

  return json(
    res,
    200,
    {
      success: true,
      ignored: true,
      event:
        eventName || null
    }
  );
}

/* =========================================================
   ROUTER API06
========================================================= */

export default async function handler(
  req,
  res
) {
  try {

    await ensureTables();

    const url =
      new URL(
        req.url,
        "http://localhost"
      );

    const action =
      clean(
        req.query?.action ||
        url.searchParams.get(
          "action"
        )
      );

    /*
     * WEBHOOK NÃO PRECISA DE SESSÃO.
     */
    if (
      action === "pay_webhook" ||
      req.headers[
        "x-pay-signature"
      ]
    ) {
      return payWebhook(
        req,
        res
      );
    }

    /*
     * Todas as outras operações
     * exigem ADMIN.
     */
    requireAdmin(req);

    let body = {};

    if (
      req.method !== "GET"
    ) {
      body =
        await requestBody(
          req
        );
    }

    switch (action) {

      case "dashboard":
      case "treasury":
        return json(
          res,
          200,
          await dashboard()
        );

      case "config":
        return json(
          res,
          200,
          await configStatus()
        );

      case "sources":
        return json(
          res,
          200,
          await sources()
        );

      case "fx":
      case "rate":
        return json(
          res,
          200,
          {
            success: true,
            ...(await fx())
          }
        );

      case "create_treasury_deposit": {

        const result =
          await createDeposit(
            body
          );

        if (
          result.order &&
          result.order.source ===
            "MPESA"
        ) {

          try {

            const payment =
              await createPayDeposit(
                result.order
              );

            return json(
              res,
              200,
              {
                ...result,
                payment
              }
            );

          } catch (e) {

            return json(
              res,
              400,
              {
                success: false,
                error:
                  e.message,
                order:
                  result.order
              }
            );
          }
        }

        return json(
          res,
          200,
          result
        );
      }

      case "deposit_status":
        return json(
          res,
          200,
          await depositStatus(
            clean(
              body.order_id ||
              req.query?.order_id ||
              url.searchParams.get(
                "order_id"
              )
            )
          )
        );

      case "convert_mzn_to_usdt":
        return json(
          res,
          200,
          await convertMZN(
            body
          )
        );

      case "reserve_usdt":
        return json(
          res,
          200,
          await reserveUSDT(
            body
          )
        );

      case "release_reservation":
        return json(
          res,
          200,
          await releaseReservation(
            body
          )
        );

      case "liquidity":
        return json(
          res,
          200,
          {
            success: true,
            ...(await realLiquidity())
          }
        );

      case "tron_usdt_balance":
      case "wallet_usdt":
        return json(
          res,
          200,
          {
            success: true,
            address:
              treasuryAddress(),
            contract:
              CONTRACT,
            usdt:
              await tronUSDTBalance()
          }
        );

      case "tron_trx_balance":
      case "wallet_trx":
        return json(
          res,
          200,
          {
            success: true,
            address:
              treasuryAddress(),
            trx:
              await tronTRXBalance()
          }
        );

      case "create_withdrawal":
      case "create_mpesawithdrawal":
      case "create_mpesa_withdrawal":
        return json(
          res,
          200,
          await createWithdrawal(
            body
          )
        );

      case "approve_withdrawal":
        return json(
          res,
          200,
          await approveWithdrawal(
            body
          )
        );

      case "process_withdrawal":
        return json(
          res,
          200,
          await processWithdrawal(
            body
          )
        );

      case "cancel_withdrawal":
        return json(
          res,
          200,
          await cancelWithdrawal(
            body
          )
        );

      case "release_failed_withdrawal":
        return json(
          res,
          200,
          await releaseFailedWithdrawal(
            body
          )
        );

      case "withdrawals":
      case "admin_withdrawals":
        return json(
          res,
          200,
          await withdrawals()
        );

      case "operations":
      case "transactions":
        return json(
          res,
          200,
          await operations()
        );

      case "pay_status":
        return json(
          res,
          200,
          {
            success: true,

            configured:
              payConfigured(),

            base_url:
              PAY_BASE,

            wallet_id:
              process.env.PAY_WALLET_ID
                ? String(
                    process.env.PAY_WALLET_ID
                  )
                : null,

            payout_destination_configured:
              Boolean(
                process.env.PAY_PAYOUT_DESTINATION
              ),

            mpesa_production:
              true,

            emola_production:
              false
          }
        );

      case "health":
        return json(
          res,
          200,
          {
            success: true,

            api:
              "API06",

            service:
              "USDTMZ CENTRAL ADMIN",

            database:
              true,

            pay:
              payConfigured(),

            tron:
              Boolean(
                process.env.TRON_PRO_API_KEY
              ),

            fx:
              Boolean(
                FX_MARKET_URL
              ),

            timestamp:
              new Date()
                .toISOString()
          }
        );

      default:
        return json(
          res,
          400,
          {
            success: false,

            error:
              "Ação API06 desconhecida.",

            api:
              "API06"
          }
        );
    }

  } catch (e) {

    console.error(
      "USDTMZ API06:",
      e
    );

    return json(
      res,
      Number(
        e?.statusCode
      ) || 500,
      {
        success: false,
        error:
          e?.message ||
          "Erro interno da API06."
      }
    );
  }
}
