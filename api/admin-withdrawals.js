// api/admin-withdrawals.js
// USDTMZ — API06 CENTRAL ADMIN / TESOURARIA
// API06 — NÃO CRIAR API13
//
// FUNÇÕES:
// - Sessão administrativa
// - Dashboard da tesouraria
// - Depósitos MZN
// - Depósitos USDT/TRC20
// - M-Pesa / e-Mola / Banco / externo / manual
// - Pay.co.mz
// - Verificação de pagamento
// - FX MZN/USDT dinâmico
// - Liquidez USDT real
// - Conversão MZN -> USDT
// - Reserva de USDT
// - Retirada MZN -> M-Pesa via Pay.co.mz
// - Aprovação de retirada
// - Webhook de pagamentos/payouts
// - Carteira TRON
// - Operações
//
// IMPORTANTE:
// Este código NÃO cria USDT artificialmente.
// treasury_wallet.usdt representa USDT real reconciliado.
// Conversão MZN -> USDT usa USDT real existente,
// aumentando a reserva, e NÃO aumenta artificialmente o saldo USDT.

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

/*
 * Taxa de mercado:
 * cache curto para evitar chamadas excessivas.
 */
const FX_CACHE_SECONDS = Number(
  process.env.FX_CACHE_SECONDS || 60
);

/*
 * Fonte pública de referência de mercado.
 *
 * IMPORTANTE:
 * Esta fonte fornece preço de mercado,
 * NÃO liquidez para comprar USDT.
 *
 * A liquidez real continua sendo verificada
 * pela carteira TRON da tesouraria.
 */
const FX_MARKET_URL =
  process.env.FX_MARKET_URL ||
  "https://api.coingecko.com/api/v3/simple/price?ids=tether&vs_currencies=mzn";

const CONTRACT =
  process.env.USDT_TRON_CONTRACT ||
  "TR7NHqjeKQXGTCi8q8ZY4pL8otSzgjLj6t";

const TRON_HOST =
  process.env.TRON_HOST ||
  "https://api.trongrid.io";

const PAY_BASE =
  process.env.PAY_API_BASE_URL ||
  "https://pay.co.mz/api/public/v1";

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

const json = (res, status, data) => {
  res.status(status);
  res.setHeader("Content-Type", "application/json");
  res.setHeader("Cache-Control", "no-store");
  res.end(JSON.stringify(data));
};

const number = v => {
  const n = Number(v);
  return Number.isFinite(n) ? n : null;
};

const positive = v => {
  const n = number(v);
  return n !== null && n > 0 ? n : null;
};

const round = (v, d = 6) =>
  Math.round(Number(v) * 10 ** d) / 10 ** d;

const reference = prefix =>
  `${prefix}-${Date.now()}-${randomBytes(8)
    .toString("hex")
    .toUpperCase()}`;

const clean = v => String(v ?? "").trim();

const upper = v => clean(v).toUpperCase();

const validSource = v =>
  DEPOSIT_SOURCES.includes(upper(v));

function cookies(req) {
  const out = {};

  for (
    const item of String(
      req.headers?.cookie || ""
    ).split(";")
  ) {
    const i = item.indexOf("=");

    if (i < 0) continue;

    const key = item.slice(0, i).trim();

    try {
      out[key] = decodeURIComponent(
        item.slice(i + 1).trim()
      );
    } catch {
      out[key] =
        item.slice(i + 1).trim();
    }
  }

  return out;
}

function safeEqual(a, b) {
  const x = Buffer.from(String(a));
  const y = Buffer.from(String(b));

  return (
    x.length === y.length &&
    timingSafeEqual(x, y)
  );
}

function admin(req) {
  const token = cookies(req)[COOKIE];
  const secret =
    process.env.ADMIN_SESSION_SECRET;

  if (!token || !secret) return null;

  const [payload, signature] =
    token.split(".");

  if (!payload || !signature) {
    return null;
  }

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
  const a = admin(req);

  if (!a) {
    const e = new Error(
      "Acesso permitido somente ao administrador."
    );

    e.statusCode = 401;

    throw e;
  }

  return a;
}

async function requestBody(req) {
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

  if (!raw) return {};

  try {
    return JSON.parse(raw);
  } catch {
    const e = new Error(
      "JSON inválido."
    );

    e.statusCode = 400;

    throw e;
  }
}

async function fetchJson(
  url,
  options = {},
  timeout = 20000
) {
  const controller =
    new AbortController();

  const timer = setTimeout(
    () => controller.abort(),
    timeout
  );

  try {
    const response =
      await fetch(url, {
        ...options,
        signal:
          controller.signal
      });

    const text =
      await response.text();

    let data = {};

    try {
      data = text
        ? JSON.parse(text)
        : {};
    } catch {
      data = {
        raw: text
      };
    }

    if (!response.ok) {
      const e = new Error(
        data?.message ||
        data?.error ||
        `HTTP ${response.status}`
      );

      e.statusCode =
        response.status;

      e.data = data;

      throw e;
    }

    return data;
  } finally {
    clearTimeout(timer);
  }
}

/* =========================================================
   DATABASE
========================================================= */

async function ensureTables() {
  await sql`
    CREATE TABLE IF NOT EXISTS treasury_wallet (
      id INTEGER PRIMARY KEY,
      mzn NUMERIC(30,8) NOT NULL DEFAULT 0,
      usdt NUMERIC(30,8) NOT NULL DEFAULT 0,
      trx NUMERIC(30,8) NOT NULL DEFAULT 0,
      reserved_usdt NUMERIC(30,8) NOT NULL DEFAULT 0,
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )
  `;

  await sql`
    INSERT INTO treasury_wallet(id)
    VALUES(1)
    ON CONFLICT(id) DO NOTHING
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
      message TEXT,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )
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

  /*
   * Retiradas administrativas.
   */
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
    CREATE INDEX IF NOT EXISTS
    transactions_provider_reference_idx
    ON transactions(provider, provider_reference)
  `;

  await sql`
    CREATE INDEX IF NOT EXISTS
    treasury_withdrawals_provider_reference_idx
    ON treasury_withdrawals(provider, provider_reference)
  `;
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
    mzn: Number(row?.mzn || 0),
    usdt: Number(row?.usdt || 0),
    trx: Number(row?.trx || 0),
    reserved_usdt:
      Number(
        row?.reserved_usdt || 0
      )
  };
}

async function availableUSDT() {
  const t =
    await treasury();

  return Math.max(
    0,
    t.usdt -
      t.reserved_usdt
  );
}

async function changeWallet(
  asset,
  amount,
  client = sql
) {
  const value =
    Number(amount);

  if (
    !Number.isFinite(value)
  ) {
    throw new Error(
      "Valor inválido."
    );
  }

  if (asset === "MZN") {
    const r =
      await client`
        UPDATE treasury_wallet
        SET
          mzn=mzn+${value},
          updated_at=NOW()
        WHERE id=1
        RETURNING *
      `;

    return r[0];
  }

  if (asset === "USDT") {
    const r =
      await client`
        UPDATE treasury_wallet
        SET
          usdt=usdt+${value},
          updated_at=NOW()
        WHERE id=1
        RETURNING *
      `;

    return r[0];
  }

  if (asset === "TRX") {
    const r =
      await client`
        UPDATE treasury_wallet
        SET
          trx=trx+${value},
          updated_at=NOW()
        WHERE id=1
        RETURNING *
      `;

    return r[0];
  }

  throw new Error(
    "Ativo inválido."
  );
}

/* =========================================================
   FX DINÂMICO
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

  /*
   * CoinGecko:
   * { tether: { mzn: 63.XX } }
   */
  const rate =
    Number(
      data?.tether?.mzn
    );

  if (
    !Number.isFinite(rate) ||
    rate <= 0
  ) {
    throw new Error(
      "Fonte de mercado não devolveu uma taxa MZN/USDT válida."
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
      new Date(now)
        .toISOString(),
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
  const market =
    await marketFX();

  return {
    currency: "MZN",
    asset: "USDT",
    rate:
      market.rate,
    source:
      market.source,
    timestamp:
      market.timestamp,
    cached:
      market.cached
  };
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

async function tronUSDTBalance() {
  const address =
    treasuryAddress();

  const tw = tron();

  const contract =
    await tw.contract()
      .at(CONTRACT);

  const balance =
    await contract
      .balanceOf(address)
      .call();

  return Number(
    tw.toBigNumber(
      balance.toString()
    )
      .dividedBy(
        10 ** USDT_DECIMALS
      )
      .toString()
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
      }
    );

  return Number(
    data?.data?.[0]
      ?.balance || 0
  ) / 1e6;
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
   PAY.CO.MZ
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

  return fetchJson(
    `${PAY_BASE}${path}`,
    {
      ...options,

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

        ...(options.headers || {})
      }
    }
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
      "e-Mola ainda não possui provedor activo em produção na PAY.co.mz."
    );
  }

  throw new Error(
    "Método Pay inválido."
  );
}

/* =========================================================
   DEPÓSITOS
========================================================= */

async function createDeposit(
  body
) {
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

  const amount =
    positive(body.amount);

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

  const orderId =
    clean(body.order_id) ||
    reference("DEP");

  const ref =
    clean(body.reference) ||
    null;

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
    source ===
      "USDT_TRON" &&
    !txHash
  ) {
    throw new Error(
      "Informe o TX Hash do depósito USDT."
    );
  }

  if (
    source ===
      "USDT_TRON" &&
    !/^[a-fA-F0-9]{20,100}$/.test(
      txHash
    )
  ) {
    throw new Error(
      "TX Hash TRON inválido."
    );
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

  const [row] =
    await sql`
      INSERT INTO treasury_deposits(
        order_id,
        source,
        amount,
        currency,
        reference,
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
        ${ref},
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
   DEPÓSITO USDT TRON
========================================================= */

async function verifyUSDTDeposit(
  order
) {
  if (!order.tx_hash) {
    throw new Error(
      "TX Hash não informado."
    );
  }

  const existing =
    await sql`
      SELECT *
      FROM blockchain_transactions
      WHERE tx_hash=${order.tx_hash}
      LIMIT 1
    `;

  if (
    existing.length &&
    existing[0].status ===
      "CONFIRMED"
  ) {
    return existing[0];
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
      }
    );

  const tx =
    data?.data?.[0];

  if (!tx) {
    throw new Error(
      "Transação TRON não encontrada."
    );
  }

  if (
    tx.ret?.[0]
      ?.contractRet &&
    tx.ret[0]
      .contractRet !==
      "SUCCESS"
  ) {
    throw new Error(
      "Transação TRON não foi concluída."
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
      }
    );

  const transfers =
    event?.data || [];

  const transfer =
    transfers.find(
      x =>
        upper(
          x?.event_name
        ) === "TRANSFER" &&
        String(
          x?.contract_address ||
            ""
        ).toLowerCase() ===
          CONTRACT.toLowerCase()
    );

  if (!transfer) {
    throw new Error(
      "Transferência USDT TRC20 não encontrada."
    );
  }

  const to =
    String(
      transfer?.result?.to ||
        ""
    );

  const expected =
    treasuryAddress();

  let decodedTo = to;

  try {
    if (
      /^[0-9a-fA-F]{40}$/.test(
        to
      )
    ) {
      decodedTo =
        TronWeb.address.fromHex(
          "41" + to
        );
    }
  } catch {}

  if (
    String(decodedTo)
      .toLowerCase() !==
    String(expected)
      .toLowerCase()
  ) {
    throw new Error(
      "O USDT não foi enviado para a carteira da tesouraria."
    );
  }

  const raw =
    Number(
      transfer?.result
        ?.value || 0
    );

  const amount =
    raw /
    10 ** USDT_DECIMALS;

  if (
    !amount ||
    amount <= 0
  ) {
    throw new Error(
      "Valor USDT inválido."
    );
  }

  const from =
    transfer?.result?.from ||
    null;

  const [saved] =
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
    Number(chain.amount);

  /*
   * Só a primeira transição
   * PENDING -> COMPLETED pode
   * gerar crédito.
   */
  const [updated] =
    await sql`
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
    `;

  if (!updated) {
    const [
      current
    ] =
      await sql`
        SELECT *
        FROM treasury_deposits
        WHERE id=${order.id}
        LIMIT 1
      `;

    return (
      current || order
    );
  }

  await changeWallet(
    "USDT",
    amount
  );

  await sql`
    UPDATE transactions
    SET
      status='COMPLETED',
      tx_hash=${order.tx_hash}
    WHERE
      reference=${order.order_id}
      AND status='PENDING'
  `;

  return updated;
}

/* =========================================================
   PAY — CRIAR COBRANÇA
========================================================= */

async function createPayDeposit(
  order
) {
  if (
    order.source !==
      "MPESA" &&
    order.source !==
      "EMOLA"
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

  const amount =
    Number(order.amount);

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
    !/^258\d{9}$/.test(
      contact
    )
  ) {
    throw new Error(
      "Número M-Pesa inválido. Use 258XXXXXXXXX."
    );
  }

  /*
   * ATENÇÃO:
   * A documentação PAY diz que /charges
   * aceita apenas:
   * amount
   * method
   * customer_name
   * customer_contact
   * wallet_id
   *
   * Portanto NÃO enviamos metadata.
   */
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
                amount,
                2
              ),

            method,

            customer_name:
              "USDTMZ Admin",

            customer_contact:
              contact,

            wallet_id:
              Number(
                process.env
                  .PAY_WALLET_ID
              )
          })
      }
    );

  const providerReference =
    clean(
      result?.reference ||
      result?.data?.reference ||
      result?.transaction_reference
    );

  if (!providerReference) {
    throw new Error(
      "PAY não devolveu a referência da cobrança."
    );
  }

  await sql`
    UPDATE treasury_deposits
    SET
      reference=${providerReference},
      message='Pagamento criado no provedor. Aguardando confirmação.',
      updated_at=NOW()
    WHERE id=${order.id}
  `;

  return {
    success: true,

    provider: true,

    provider_reference:
      providerReference,

    status:
      result?.status ||
      result?.data?.state ||
      "PENDING",

    checkout_url:
      result?.checkout_url ||
      result?.data?.checkout_url ||
      null
  };
}

/* =========================================================
   STATUS DEPÓSITO
========================================================= */

async function depositStatus(
  orderId
) {
  if (!orderId) {
    throw new Error(
      "order_id obrigatório."
    );
  }

  const [order] =
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

  /*
   * A taxa é sempre obtida
   * pelo servidor.
   */
  const market =
    await marketFX();

  const rate =
    market.rate;

  const usdt =
    calculateUSDT(
      amount,
      rate
    );

  if (
    !Number.isFinite(usdt) ||
    usdt <= 0
  ) {
    throw new Error(
      "Quantidade USDT inválida."
    );
  }

  /*
   * Verifica USDT REAL.
   */
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

      rate,

      rate_source:
        market.source,

      rate_timestamp:
        market.timestamp
    };
  }

  /*
   * Verifica MZN real
   * contabilizado na tesouraria.
   */
  const wallet =
    await treasury();

  if (
    wallet.mzn <
    amount
  ) {
    throw new Error(
      "Saldo MZN insuficiente na tesouraria."
    );
  }

  /*
   * NÃO fazemos:
   *
   * changeWallet("USDT", usdt)
   *
   * porque isso criaria USDT
   * contabilístico.
   *
   * O USDT já existe.
   *
   * A conversão passa a reservá-lo.
   */

  const debit =
    await sql`
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
    `;

  if (!debit.length) {
    return {
      success: false,
      status:
        "INDISPONIVEL",
      reason:
        "SALDO_OU_LIQUIDEZ_ALTERADO"
    };
  }

  const ref =
    reference("CONV");

  await sql`
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
      ${rate},
      'COMPLETED'
    )
  `;

  await sql`
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
  `;

  await sql`
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
  `;

  return {
    success: true,

    status:
      "COMPLETED",

    reference:
      ref,

    mzn:
      amount,

    usdt,

    rate,

    rate_source:
      market.source,

    rate_timestamp:
      market.timestamp,

    note:
      "USDT proveniente da liquidez real da tesouraria; nenhum USDT foi criado artificialmente."
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
    clean(body.reason) ||
    "Reserva administrativa";

  const ref =
    reference("RES");

  const [row] =
    await sql`
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
    `;

  if (!row) {
    throw new Error(
      "USDT disponível insuficiente."
    );
  }

  await sql`
    INSERT INTO treasury_reservations(
      reference,
      usdt_amount,
      reason
    )
    VALUES(
      ${ref},
      ${amount},
      ${reason}
    )
  `;

  return {
    success: true,
    reference: ref,
    amount_usdt:
      amount,
    status:
      "RESERVED"
  };
}

/* =========================================================
   LIBERTAR RESERVA
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

  const [
    reservation
  ] =
    await sql`
      SELECT *
      FROM treasury_reservations
      WHERE reference=${ref}
      LIMIT 1
    `;

  if (!reservation) {
    throw new Error(
      "Reserva não encontrada."
    );
  }

  if (
    reservation.status !==
    "RESERVED"
  ) {
    return {
      success: true,
      already_processed: true
    };
  }

  const amount =
    Number(
      reservation.usdt_amount
    );

  const [changed] =
    await sql`
      UPDATE treasury_reservations
      SET status='RELEASED'
      WHERE
        reference=${ref}
        AND status='RESERVED'
      RETURNING *
    `;

  if (!changed) {
    return {
      success: true,
      already_processed: true
    };
  }

  await sql`
    UPDATE treasury_wallet
    SET
      reserved_usdt=
        GREATEST(
          0,
          reserved_usdt-${amount}
        ),
      updated_at=NOW()
    WHERE id=1
  `;

  return {
    success: true,
    reference: ref,
    amount_usdt:
      amount,
    status:
      "RELEASED"
  };
}

/* =========================================================
   RETIRADA MZN -> M-PESA
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
    method !==
    "MPESA"
  ) {
    throw new Error(
      "Nesta integração PAY, a retirada automática implementada é M-Pesa."
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

  /*
   * O endpoint /payouts documentado
   * usa o Wallet ID da PAY.
   *
   * Não inventamos destination/phone
   * porque esses campos não aparecem
   * no contrato da API fornecido.
   */
  if (!payConfigured()) {
    throw new Error(
      "PAY.co.mz não está configurado."
    );
  }

  const wallet =
    await treasury();

  if (
    wallet.mzn <
    amount
  ) {
    throw new Error(
      "Saldo MZN insuficiente."
    );
  }

  const ref =
    reference("WD");

  /*
   * Criamos primeiro como PENDING.
   * Nenhum dinheiro sai nesta etapa.
   */
  const [row] =
    await sql`
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
        NULL,
        'PENDING',
        'PENDING',
        'PAY',
        'Aguardando aprovação administrativa.'
      )
      RETURNING *
    `;

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
      "Retirada criada. É necessária aprovação do administrador antes do payout."
  };
}

/* =========================================================
   APROVAR E EXECUTAR PAYOUT
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

  const [withdrawal] =
    await sql`
      SELECT *
      FROM treasury_withdrawals
      WHERE reference=${ref}
      LIMIT 1
    `;

  if (!withdrawal) {
    throw new Error(
      "Retirada não encontrada."
    );
  }

  if (
    withdrawal.status ===
    "COMPLETED"
  ) {
    return {
      success: true,
      already_completed: true,
      withdrawal
    };
  }

  if (
    withdrawal.approval_status ===
    "APPROVED" &&
    withdrawal.provider_reference
  ) {
    return {
      success: true,
      already_submitted: true,
      withdrawal
    };
  }

  if (
    withdrawal.method !==
    "MPESA"
  ) {
    throw new Error(
      "Método de retirada inválido."
    );
  }

  const amount =
    Number(
      withdrawal.amount
    );

  /*
   * Reserva o MZN de forma atómica.
   *
   * Apenas uma execução pode conseguir
   * debitar o saldo.
   */
  const [debited] =
    await sql`
      UPDATE treasury_wallet
      SET
        mzn=mzn-${amount},
        updated_at=NOW()
      WHERE
        id=1
        AND mzn>=${amount}
      RETURNING *
    `;

  if (!debited) {
    throw new Error(
      "Saldo MZN insuficiente no momento da aprovação."
    );
  }

  /*
   * Marca APPROVED antes do pedido externo.
   */
  await sql`
    UPDATE treasury_withdrawals
    SET
      approval_status='APPROVED',
      status='PROCESSING',
      updated_at=NOW(),
      message='Retirada aprovada; payout enviado para a PAY.'
    WHERE
      id=${withdrawal.id}
      AND status='PENDING'
      AND approval_status='PENDING'
  `;

  try {
    /*
     * PAY /payouts:
     * a documentação fornecida aceita amount.
     *
     * O destino é o M-Pesa configurado
     * na carteira PAY.
     */
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

    const providerId =
      clean(
        result?.id ||
        result?.data?.id
      ) || null;

    const providerStatus =
      upper(
        result?.status ||
        result?.data?.status ||
        result?.state ||
        result?.data?.state ||
        "PROCESSING"
      );

    /*
     * O payout pode ser aceite,
     * mas NÃO significa ainda PAID.
     */
    await sql`
      UPDATE treasury_withdrawals
      SET
        provider='PAY',
        provider_reference=
          ${providerId},
        provider_id=
          ${providerId},
        status=
          ${
            [
              "PAID",
              "SUCCESS",
              "SUCCEEDED",
              "COMPLETED"
            ].includes(
              providerStatus
            )
              ? "COMPLETED"
              : "PROCESSING"
          },
        message=
          'Payout submetido à PAY.co.mz.',
        updated_at=NOW()
      WHERE id=${withdrawal.id}
    `;

    /*
     * Se a PAY já devolver PAID,
     * concluímos.
     *
     * Normalmente o webhook
     * fará a confirmação final.
     */
    if (
      [
        "PAID",
        "SUCCESS",
        "SUCCEEDED",
        "COMPLETED"
      ].includes(
        providerStatus
      )
    ) {
      await sql`
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
          ${providerId}
        )
        ON CONFLICT(reference)
        DO NOTHING
      `;
    }

    const [
      updated
    ] =
      await sql`
        SELECT *
        FROM treasury_withdrawals
        WHERE id=${withdrawal.id}
        LIMIT 1
      `;

    return {
      success: true,

      status:
        updated?.status ||
        "PROCESSING",

      approval_status:
        "APPROVED",

      reference:
        ref,

      provider:
        "PAY",

      provider_id:
        providerId,

      payout:
        result,

      withdrawal:
        updated
    };
  } catch (e) {
    /*
     * O payout falhou.
     *
     * Devolvemos o MZN à tesouraria.
     */
    await sql`
      UPDATE treasury_wallet
      SET
        mzn=mzn+${amount},
        updated_at=NOW()
      WHERE id=1
    `;

    await sql`
      UPDATE treasury_withdrawals
      SET
        status='FAILED',
        message=${e.message},
        updated_at=NOW()
      WHERE id=${withdrawal.id}
    `;

    throw e;
  }
}

/* =========================================================
   CANCELAR RETIRADA PENDING
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

  const [row] =
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
      "A retirada não está PENDING ou já foi processada."
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

      available_usdt:
        Math.max(
          0,
          wallet.usdt -
            wallet.reserved_usdt
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
        pendingWithdrawals
          ?.count || 0
      ),

    status:
      liquidity
        .real_available_usdt >
      0
        ? "LIQUIDEZ_DISPONIVEL"
        : "SEM_LIQUIDEZ"
  };
}

/* =========================================================
   OPERAÇÕES
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
   FONTES
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
              process.env
                .PAY_WALLET_ID
            )
          : null
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

async function config() {
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

    deposit_methods:
      DEPOSIT_SOURCES,

    withdrawal_methods:
      [
        "MPESA"
      ]
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
    const [key, ...rest] =
      part.split("=");

    if (key) {
      out[key.trim()] =
        rest.join("=")
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

  let raw = "";

  for await (
    const chunk of req
  ) {
    raw += chunk.toString();
  }

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
      event?.event ||
      req.headers[
        "x-pay-event"
      ]
    );

  const data =
    event?.data ||
    event?.payment ||
    event?.charge ||
    event;

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
        data?.transaction_reference
      );

    const [withdrawal] =
      await sql`
        SELECT *
        FROM treasury_withdrawals
        WHERE
          provider_id=${providerId}
          OR provider_reference=${providerReference}
        ORDER BY id DESC
        LIMIT 1
      `;

    if (!withdrawal) {
      return json(
        res,
        200,
        {
          success: true,
          ignored: true,
          reason:
            "Payout não associado ao USDTMZ."
        }
      );
    }

    const amount =
      Number(
        withdrawal.amount
      );

    const [changed] =
      await sql`
        UPDATE treasury_withdrawals
        SET
          status='COMPLETED',
          message='Payout M-Pesa confirmado pela PAY.',
          updated_at=NOW()
        WHERE
          id=${withdrawal.id}
          AND status <> 'COMPLETED'
        RETURNING *
      `;

    if (changed) {
      await sql`
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
          ${providerReference || providerId}
        )
        ON CONFLICT(reference)
        DO UPDATE SET
          status='COMPLETED'
      `;
    }

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
        data?.transaction_reference
      );

    const [withdrawal] =
      await sql`
        SELECT *
        FROM treasury_withdrawals
        WHERE
          provider_id=${providerId}
          OR provider_reference=${providerReference}
        ORDER BY id DESC
        LIMIT 1
      `;

    if (!withdrawal) {
      return json(
        res,
        200,
        {
          success: true,
          ignored: true
        }
      );
    }

    const amount =
      Number(
        withdrawal.amount
      );

    const [changed] =
      await sql`
        UPDATE treasury_withdrawals
        SET
          status='FAILED',
          message='Payout recusado/falhado pela PAY.',
          updated_at=NOW()
        WHERE
          id=${withdrawal.id}
          AND status <> 'FAILED'
          AND status <> 'COMPLETED'
        RETURNING *
      `;

    /*
     * Só devolve MZN se esta transição
     * realmente aconteceu.
     */
    if (changed) {
      await sql`
        UPDATE treasury_wallet
        SET
          mzn=mzn+${amount},
          updated_at=NOW()
        WHERE id=1
      `;
    }

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
     PAYMENT SUCCEEDED
  ======================================================= */

  if (
    eventName ===
      "payment.succeeded"
  ) {
    const providerReference =
      clean(
        data?.reference ||
        data?.transaction_reference
      );

    if (!providerReference) {
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
     * A PAY não documenta metadata no /charges.
     * Portanto encontramos a ordem pela referência PAY.
     */
    const [order] =
      await sql`
        SELECT *
        FROM treasury_deposits
        WHERE
          reference=${providerReference}
        LIMIT 1
      `;

    if (!order) {
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

    const amount =
      Number(
        order.amount
      );

    /*
     * Apenas a primeira transição
     * PENDING -> COMPLETED deve
     * gerar crédito MZN.
     */
    const [changed] =
      await sql`
        UPDATE treasury_deposits
        SET
          status='COMPLETED',
          message='Pagamento confirmado pela PAY.',
          updated_at=NOW()
        WHERE
          id=${order.id}
          AND status='PENDING'
        RETURNING *
      `;

    if (changed) {
      await changeWallet(
        "MZN",
        amount
      );

      await sql`
        UPDATE transactions
        SET
          status='COMPLETED',
          provider='PAY',
          provider_reference=${providerReference}
        WHERE
          reference=${order.order_id}
          AND status='PENDING'
      `;
    }

    return json(
      res,
      200,
      {
        success: true,
        event:
          eventName,
        order_id:
          order.order_id,
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
      clean(
        data?.reference ||
        data?.transaction_reference
      );

    if (providerReference) {
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
    }

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
     * Webhooks PAY não usam
     * sessão administrativa.
     */
    if (
      action ===
        "pay_webhook" ||
      req.headers[
        "x-pay-signature"
      ]
    ) {
      return payWebhook(
        req,
        res
      );
    }

    requireAdmin(req);

    const body =
      await requestBody(req);

    switch (action) {

      /* =========================
         DASHBOARD
      ========================= */

      case "dashboard":
      case "treasury":
        return json(
          res,
          200,
          await dashboard()
        );

      /* =========================
         CONFIG
      ========================= */

      case "config":
        return json(
          res,
          200,
          await config()
        );

      /* =========================
         FONTES
      ========================= */

      case "sources":
        return json(
          res,
          200,
          await sources()
        );

      /* =========================
         FX
      ========================= */

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

      /* =========================
         CRIAR DEPÓSITO
      ========================= */

      case "create_treasury_deposit": {
        const result =
          await createDeposit(
            body
          );

        if (
          result.order &&
          (
            result.order.source ===
              "MPESA" ||
            result.order.source ===
              "EMOLA"
          )
        ) {
          try {
            const payResult =
              await createPayDeposit(
                result.order
              );

            return json(
              res,
              200,
              {
                ...result,
                payment:
                  payResult
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

      /* =========================
         STATUS DEPÓSITO
      ========================= */

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

      /* =========================
         CONVERSÃO
      ========================= */

      case "convert_mzn_to_usdt":
        return json(
          res,
          200,
          await convertMZN(
            body
          )
        );

      /* =========================
         RESERVA USDT
      ========================= */

      case "reserve_usdt":
        return json(
          res,
          200,
          await reserveUSDT(
            body
          )
        );

      /* =========================
         LIBERTAR RESERVA
      ========================= */

      case "release_reservation":
        return json(
          res,
          200,
          await releaseReservation(
            body
          )
        );

      /* =========================
         LIQUIDEZ
      ========================= */

      case "liquidity":
        return json(
          res,
          200,
          {
            success: true,
            ...(await realLiquidity())
          }
        );

      /* =========================
         TRON USDT
      ========================= */

      case "tron_usdt_balance":
      case "wallet_usdt":
        return json(
          res,
          200,
          {
            success: true,

            address:
              treasuryAddress(),

            usdt:
              await tronUSDTBalance()
          }
        );

      /* =========================
         TRON TRX
      ========================= */

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

      /* =========================
         CRIAR RETIRADA
      ========================= */

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

      /* =========================
         APROVAR RETIRADA
      ========================= */

      case "approve_withdrawal":
      case "process_withdrawal":
        return json(
          res,
          200,
          await approveWithdrawal(
            body
          )
        );

      /* =========================
         CANCELAR RETIRADA
      ========================= */

      case "cancel_withdrawal":
        return json(
          res,
          200,
          await cancelWithdrawal(
            body
          )
        );

      /* =========================
         LISTAR RETIRADAS
      ========================= */

      case "withdrawals":
      case "admin_withdrawals":
        return json(
          res,
          200,
          await withdrawals()
        );

      /* =========================
         OPERAÇÕES
      ========================= */

      case "operations":
      case "transactions":
        return json(
          res,
          200,
          await operations()
        );

      /* =========================
         PAY STATUS
      ========================= */

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
              process.env
                .PAY_WALLET_ID
                ? String(
                    process.env
                      .PAY_WALLET_ID
                  )
                : null
          }
        );

      /* =========================
         HEALTH
      ========================= */

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
