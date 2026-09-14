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
// - FX MZN/USD/USDT
// - Liquidez USDT real
// - Conversão MZN -> USDT
// - Reserva de USDT
// - Carteira TRON
// - Operações
//
// IMPORTANTE:
// Este código NÃO cria USDT artificialmente.
// USDT disponível deve representar fundos reais da tesouraria.

import { createHmac, timingSafeEqual, randomBytes } from "node:crypto";
import { neon } from "@neondatabase/serverless";
import { TronWeb } from "tronweb";

const sql = neon(process.env.DATABASE_URL);

const COOKIE = "usdtmz_admin_session";

const MIN_MZN = 20;
const MAX_MZN = 40000;

const USDT_DECIMALS = 6;

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

  for (const item of String(req.headers?.cookie || "").split(";")) {
    const i = item.indexOf("=");

    if (i < 0) continue;

    const key = item.slice(0, i).trim();

    try {
      out[key] = decodeURIComponent(
        item.slice(i + 1).trim()
      );
    } catch {
      out[key] = item.slice(i + 1).trim();
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
  const secret = process.env.ADMIN_SESSION_SECRET;

  if (!token || !secret) return null;

  const [payload, signature] = token.split(".");

  if (!payload || !signature) return null;

  const expected = createHmac(
    "sha256",
    secret
  )
    .update(payload)
    .digest("base64url");

  if (!safeEqual(signature, expected)) return null;

  try {
    const data = JSON.parse(
      Buffer.from(payload, "base64url").toString()
    );

    if (
      data?.id !== "admin" ||
      !data?.email ||
      Number(data?.exp) <= Date.now()
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
    const e = new Error("JSON inválido.");
    e.statusCode = 400;
    throw e;
  }
}

async function fetchJson(
  url,
  options = {},
  timeout = 20000
) {
  const controller = new AbortController();

  const timer = setTimeout(
    () => controller.abort(),
    timeout
  );

  try {
    const response = await fetch(url, {
      ...options,
      signal: controller.signal
    });

    const text = await response.text();

    let data = {};

    try {
      data = text ? JSON.parse(text) : {};
    } catch {
      data = { raw: text };
    }

    if (!response.ok) {
      const e = new Error(
        data?.message ||
        data?.error ||
        `HTTP ${response.status}`
      );

      e.statusCode = response.status;
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

  await sql`
    CREATE INDEX IF NOT EXISTS
    transactions_provider_reference_idx
    ON transactions(provider, provider_reference)
  `;
}

/* =========================================================
   TREASURY
========================================================= */

async function treasury() {
  const [row] = await sql`
    SELECT *
    FROM treasury_wallet
    WHERE id=1
  `;

  return {
    mzn: Number(row?.mzn || 0),
    usdt: Number(row?.usdt || 0),
    trx: Number(row?.trx || 0),
    reserved_usdt: Number(
      row?.reserved_usdt || 0
    )
  };
}

async function availableUSDT() {
  const t = await treasury();

  return Math.max(
    0,
    t.usdt - t.reserved_usdt
  );
}

async function changeWallet(
  asset,
  amount,
  client = sql
) {
  const value = Number(amount);

  if (!Number.isFinite(value)) {
    throw new Error("Valor inválido.");
  }

  if (asset === "MZN") {
    const r = await client`
      UPDATE treasury_wallet
      SET mzn=mzn+${value},
          updated_at=NOW()
      WHERE id=1
      RETURNING *
    `;

    return r[0];
  }

  if (asset === "USDT") {
    const r = await client`
      UPDATE treasury_wallet
      SET usdt=usdt+${value},
          updated_at=NOW()
      WHERE id=1
      RETURNING *
    `;

    return r[0];
  }

  if (asset === "TRX") {
    const r = await client`
      UPDATE treasury_wallet
      SET trx=trx+${value},
          updated_at=NOW()
      WHERE id=1
      RETURNING *
    `;

    return r[0];
  }

  throw new Error("Ativo inválido.");
}

/* =========================================================
   FX
========================================================= */

function configuredRate() {
  const rate = Number(
    process.env.USDT_MZN_RATE || 0
  );

  if (!Number.isFinite(rate) || rate <= 0) {
    throw new Error(
      "USDT_MZN_RATE não configurado."
    );
  }

  return rate;
}

function calculateUSDT(
  mzn,
  rate
) {
  return round(
    Number(mzn) / Number(rate),
    USDT_DECIMALS
  );
}

async function fx() {
  const rate = configuredRate();

  return {
    currency: "MZN",
    asset: "USDT",
    rate,
    source:
      process.env.USDT_MZN_RATE_SOURCE ||
      "SERVER_CONFIG",
    timestamp: new Date().toISOString()
  };
}

/* =========================================================
   TRON
========================================================= */

function tronAddress(address) {
  try {
    return Boolean(
      address &&
      TronWeb.isAddress(String(address).trim())
    );
  } catch {
    return false;
  }
}

function tron() {
  const options = {
    fullHost: TRON_HOST
  };

  if (process.env.TRON_PRO_API_KEY) {
    options.headers = {
      "TRON-PRO-API-KEY":
        process.env.TRON_PRO_API_KEY
    };
  }

  return new TronWeb(options);
}

function treasuryAddress() {
  const address = clean(
    process.env.TREASURY_TRON_ADDRESS ||
    process.env.USDTMZ_TRON_WALLET_ADDRESS ||
    process.env.TRON_TREASURY_ADDRESS
  );

  if (!tronAddress(address)) {
    throw new Error(
      "Endereço TRON da tesouraria inválido."
    );
  }

  return address;
}

async function tronUSDTBalance() {
  const address = treasuryAddress();
  const tw = tron();

  const contract =
    await tw.contract().at(CONTRACT);

  const balance =
    await contract.balanceOf(address).call();

  return Number(
    tw.toBigNumber(balance.toString())
      .dividedBy(10 ** USDT_DECIMALS)
      .toString()
  );
}

async function tronTRXBalance() {
  const address = treasuryAddress();

  const data = await fetchJson(
    `${TRON_HOST}/v1/accounts/${address}`,
    {
      headers: process.env.TRON_PRO_API_KEY
        ? {
            "TRON-PRO-API-KEY":
              process.env.TRON_PRO_API_KEY
          }
        : {}
    }
  );

  return Number(
    data?.data?.[0]?.balance || 0
  ) / 1e6;
}

/* =========================================================
   LIQUIDEZ REAL
========================================================= */

async function realLiquidity() {
  const internal = await treasury();

  let chainUSDT = null;
  let chainTRX = null;

  try {
    chainUSDT = await tronUSDTBalance();
  } catch (e) {
    console.error(
      "TRON USDT:",
      e.message
    );
  }

  try {
    chainTRX = await tronTRXBalance();
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
      ? internalAvailable
      : Math.min(
          internalAvailable,
          chainUSDT
        );

  return {
    internal_usdt: internal.usdt,
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

async function pay(path, options = {}) {
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

        Accept: "application/json",

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
  const m = clean(method).toLowerCase();

  if (m === "mpesa") return "mpesa";

  if (m === "emola") {
    if (
      String(
        process.env.PAY_SUPPORTS_EMOLA
      ).toLowerCase() !== "true"
    ) {
      throw new Error(
        "e-Mola requer um provedor/end-point configurado para e-Mola."
      );
    }

    return "emola";
  }

  throw new Error(
    "Método Pay inválido."
  );
}

/* =========================================================
   CRIAÇÃO DE DEPÓSITO
========================================================= */

async function createDeposit(body) {
  const source = upper(
    body.source || body.method
  );

  if (!validSource(source)) {
    throw new Error(
      "Método de depósito inválido."
    );
  }

  const amount = positive(
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
      (source === "USDT_TRON"
        ? "USDT"
        : "MZN")
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
    source === "USDT_TRON" &&
    !txHash
  ) {
    throw new Error(
      "Informe o TX Hash do depósito USDT."
    );
  }

  if (
    source === "USDT_TRON" &&
    !/^[a-fA-F0-9]{20,100}$/.test(
      txHash
    )
  ) {
    throw new Error(
      "TX Hash TRON inválido."
    );
  }

  const [existing] = await sql`
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

  const [row] = await sql`
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
    ON CONFLICT(reference) DO NOTHING
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

async function verifyUSDTDeposit(order) {
  if (!order.tx_hash) {
    throw new Error(
      "TX Hash não informado."
    );
  }

  const existing = await sql`
    SELECT *
    FROM blockchain_transactions
    WHERE tx_hash=${order.tx_hash}
    LIMIT 1
  `;

  if (
    existing.length &&
    existing[0].status === "CONFIRMED"
  ) {
    return existing[0];
  }

  const data = await fetchJson(
    `${TRON_HOST}/v1/transactions/${order.tx_hash}`,
    {
      headers: process.env.TRON_PRO_API_KEY
        ? {
            "TRON-PRO-API-KEY":
              process.env.TRON_PRO_API_KEY
          }
        : {}
    }
  );

  const tx = data?.data?.[0];

  if (!tx) {
    throw new Error(
      "Transação TRON não encontrada."
    );
  }

  if (
    tx.ret?.[0]?.contractRet &&
    tx.ret[0].contractRet !== "SUCCESS"
  ) {
    throw new Error(
      "Transação TRON não foi concluída."
    );
  }

  const event = await fetchJson(
    `${TRON_HOST}/v1/transactions/${order.tx_hash}/events`,
    {
      headers: process.env.TRON_PRO_API_KEY
        ? {
            "TRON-PRO-API-KEY":
              process.env.TRON_PRO_API_KEY
          }
        : {}
    }
  );

  const transfers =
    event?.data || [];

  const transfer = transfers.find(
    x =>
      upper(x?.event_name) ===
        "TRANSFER" &&
      String(
        x?.contract_address
      ).toLowerCase() ===
        CONTRACT.toLowerCase()
  );

  if (!transfer) {
    throw new Error(
      "Transferência USDT TRC20 não encontrada."
    );
  }

  const to = String(
    transfer?.result?.to || ""
  );

  const expected =
    treasuryAddress();

  let decodedTo = to;

  try {
    if (
      /^[0-9a-fA-F]{40}$/.test(to)
    ) {
      decodedTo =
        TronWeb.address.fromHex(
          "41" + to
        );
    }
  } catch {}

  if (
    String(decodedTo).toLowerCase() !==
    String(expected).toLowerCase()
  ) {
    throw new Error(
      "O USDT não foi enviado para a carteira da tesouraria."
    );
  }

  const raw = Number(
    transfer?.result?.value || 0
  );

  const amount =
    raw / 10 ** USDT_DECIMALS;

  if (!amount || amount <= 0) {
    throw new Error(
      "Valor USDT inválido."
    );
  }

  const from =
    transfer?.result?.from ||
    null;

  const [saved] = await sql`
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

async function confirmUSDTDeposit(order) {
  const chain =
    await verifyUSDTDeposit(order);

  const [current] = await sql`
    SELECT *
    FROM treasury_deposits
    WHERE id=${order.id}
    FOR UPDATE
  `;

  if (
    current?.status ===
    "COMPLETED"
  ) {
    return current;
  }

  const amount =
    Number(chain.amount);

  await changeWallet(
    "USDT",
    amount
  );

  const [updated] = await sql`
    UPDATE treasury_deposits
    SET
      amount=${amount},
      currency='USDT',
      usdt_amount=${amount},
      status='COMPLETED',
      message='USDT confirmado na blockchain.',
      updated_at=NOW()
    WHERE id=${order.id}
    RETURNING *
  `;

  return updated;
}

/* =========================================================
   PAY M-PESA
========================================================= */

async function createPayDeposit(order) {
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
    payMethod(order.source);

  const amount =
    Number(order.amount);

  let contact =
    clean(order.payment_phone);

  contact =
    contact.replace(/\D/g, "");

  if (/^\d{9}$/.test(contact)) {
    contact =
      "258" + contact;
  }

  if (!/^258\d{9}$/.test(contact)) {
    throw new Error(
      "Número de pagamento inválido."
    );
  }

  const result =
    await pay("/charges", {
      method: "POST",

      headers: {
        "Idempotency-Key":
          `usdtmz-${order.order_id}`
      },

      body: JSON.stringify({
        amount: round(
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
            process.env.PAY_WALLET_ID
          ),

        metadata: {
          usdtmz_order_id:
            order.order_id
        }
      })
    });

  const providerReference =
    clean(
      result?.reference ||
      result?.charge?.reference ||
      result?.data?.reference ||
      result?.transaction_reference
    );

  await sql`
    UPDATE treasury_deposits
    SET
      reference=COALESCE(
        reference,
        ${providerReference || null}
      ),
      message='Pagamento criado no provedor. Aguardando confirmação.',
      updated_at=NOW()
    WHERE id=${order.id}
  `;

  return {
    success: true,
    provider: true,
    provider_reference:
      providerReference || null,

    status:
      result?.status ||
      "PROCESSING",

    checkout_url:
      result?.checkout_url ||
      result?.charge?.checkout_url ||
      result?.data?.checkout_url ||
      null
  };
}

/* =========================================================
   STATUS DO DEPÓSITO
========================================================= */

async function depositStatus(orderId) {
  const [order] = await sql`
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
        status: order.status,
        message: e.message,
        order
      };
    }
  }

  return {
    success: true,
    confirmed: false,
    status: order.status,
    order
  };
}

/* =========================================================
   CONVERSÃO MZN -> USDT
========================================================= */

async function convertMZN(body) {
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

  const rate =
    configuredRate();

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
   * IMPORTANTE:
   * Consultamos a liquidez real antes
   * de fazer qualquer crédito.
   */

  const liquidity =
    await realLiquidity();

  if (
    liquidity.real_available_usdt <
    usdt
  ) {
    return {
      success: false,
      status: "INDISPONIVEL",
      reason:
        "LIQUIDEZ_USDT_INSUFICIENTE",
      requested_usdt: usdt,
      available_usdt:
        liquidity.real_available_usdt,
      rate
    };
  }

  /*
   * Verifica MZN interno.
   */

  const wallet =
    await treasury();

  if (
    wallet.mzn < amount
  ) {
    throw new Error(
      "Saldo MZN insuficiente na tesouraria."
    );
  }

  /*
   * Débito MZN.
   */

  const debit =
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

  if (!debit.length) {
    throw new Error(
      "Não foi possível reservar o MZN."
    );
  }

  /*
   * Antes de creditar USDT,
   * verificar novamente.
   */

  const second =
    await realLiquidity();

  if (
    second.real_available_usdt <
    usdt
  ) {
    await sql`
      UPDATE treasury_wallet
      SET
        mzn=mzn+${amount},
        updated_at=NOW()
      WHERE id=1
    `;

    return {
      success: false,
      status: "INDISPONIVEL",
      reason:
        "LIQUIDEZ_ALTERADA_DURANTE_OPERACAO",
      requested_usdt: usdt
    };
  }

  await changeWallet(
    "USDT",
    usdt
  );

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
    status: "COMPLETED",
    reference: ref,
    mzn: amount,
    usdt,
    rate
  };
}

/* =========================================================
   RESERVA USDT
========================================================= */

async function reserveUSDT(body) {
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
    amount_usdt: amount,
    status: "RESERVED"
  };
}

/* =========================================================
   LIBERTAR RESERVA
========================================================= */

async function releaseReservation(body) {
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

  const [reservation] =
    await sql`
      SELECT *
      FROM treasury_reservations
      WHERE reference=${ref}
      FOR UPDATE
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

  await sql`
    UPDATE treasury_reservations
    SET status='RELEASED'
    WHERE reference=${ref}
  `;

  return {
    success: true,
    reference: ref,
    amount_usdt: amount,
    status: "RELEASED"
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

  const rate =
    configuredRate();

  const [pending] =
    await sql`
      SELECT COUNT(*)::int AS count
      FROM treasury_deposits
      WHERE status='PENDING'
    `;

  return {
    success: true,

    treasury: {
      mzn: wallet.mzn,
      usdt: wallet.usdt,
      trx: wallet.trx,
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
      mzn_usdt: rate
    },

    pending_deposits:
      Number(
        pending?.count || 0
      ),

    status:
      liquidity.real_available_usdt >
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

  return {
    success: true,
    deposits,
    conversions
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
        payConfigured()
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
   CONFIGURAÇÃO
========================================================= */

async function config() {
  return {
    success: true,

    currency: "MZN",

    asset: "USDT",

    network: "TRON/TRC20",

    min_mzn: MIN_MZN,

    max_mzn: MAX_MZN,

    rate: configuredRate(),

    contract: CONTRACT,

    pay_configured:
      payConfigured(),

    deposit_methods:
      DEPOSIT_SOURCES
  };
}

/* =========================================================
   PAY WEBHOOK
========================================================= */

function parsePaySignature(value) {
  const out = {};

  for (
    const part of String(
      value || ""
    ).split(",")
  ) {
    const [key, ...rest] =
      part.split("=");

    if (key) {
      out[key] =
        rest.join("=");
    }
  }

  if (
    out.t &&
    out.v1
  ) {
    return {
      timestamp: out.t,
      signature: out.v1
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
    event = JSON.parse(raw);
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

  const data =
    event?.data ||
    event?.payment ||
    event?.charge ||
    event;

  const orderId =
    clean(
      data?.metadata
        ?.usdtmz_order_id ||
      data?.metadata
        ?.order_id
    );

  const providerReference =
    clean(
      data?.reference ||
      data?.transaction_reference ||
      data?.charge?.reference
    );

  const status =
    upper(
      data?.status
    );

  if (
    !orderId
  ) {
    return json(
      res,
      200,
      {
        success: true,
        ignored: true
      }
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
    return json(
      res,
      404,
      {
        success: false,
        error:
          "Pedido USDTMZ não encontrado."
      }
    );
  }

  if (
    [
      "PAID",
      "SUCCESS",
      "SUCCEEDED",
      "COMPLETED"
    ].includes(status)
  ) {
    await sql`
      UPDATE treasury_deposits
      SET
        status='COMPLETED',
        reference=COALESCE(
          reference,
          ${providerReference || null}
        ),
        message=
          'Pagamento confirmado pelo provedor.',
        updated_at=NOW()
      WHERE
        id=${order.id}
        AND status='PENDING'
    `;

    const amount =
      Number(order.amount);

    /*
     * Só credita MZN uma vez.
     */
    const [tx] =
      await sql`
        SELECT *
        FROM transactions
        WHERE reference=${order.order_id}
        LIMIT 1
      `;

    if (
      tx &&
      tx.status === "PENDING"
    ) {
      await changeWallet(
        "MZN",
        amount
      );

      await sql`
        UPDATE transactions
        SET status='COMPLETED'
        WHERE id=${tx.id}
          AND status='PENDING'
      `;
    }
  }

  return json(
    res,
    200,
    {
      success: true,
      order_id: orderId,
      status
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

    /*
     * Webhook não usa sessão de admin.
     */
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
     * Webhook Pay
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
     * Todas as restantes funções
     * exigem administrador.
     */
    requireAdmin(req);

    const body =
      await requestBody(req);

    switch (action) {
      /* -------------------------
         DASHBOARD
      ------------------------- */

      case "dashboard":
      case "treasury":
        return json(
          res,
          200,
          await dashboard()
        );

      /* -------------------------
         CONFIG
      ------------------------- */

      case "config":
        return json(
          res,
          200,
          await config()
        );

      /* -------------------------
         FONTES
      ------------------------- */

      case "sources":
        return json(
          res,
          200,
          await sources()
        );

      /* -------------------------
         FX
      ------------------------- */

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

      /* -------------------------
         CRIAR DEPÓSITO
      ------------------------- */

      case "create_treasury_deposit": {
        const result =
          await createDeposit(
            body
          );

        /*
         * Para M-Pesa/e-Mola,
         * cria a cobrança no provedor.
         */
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
                error: e.message,
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

      /* -------------------------
         STATUS DEPÓSITO
      ------------------------- */

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

      /* -------------------------
         CONVERSÃO
      ------------------------- */

      case "convert_mzn_to_usdt":
        return json(
          res,
          200,
          await convertMZN(
            body
          )
        );

      /* -------------------------
         RESERVAR USDT
      ------------------------- */

      case "reserve_usdt":
        return json(
          res,
          200,
          await reserveUSDT(
            body
          )
        );

      /* -------------------------
         LIBERTAR RESERVA
      ------------------------- */

      case "release_reservation":
        return json(
          res,
          200,
          await releaseReservation(
            body
          )
        );

      /* -------------------------
         LIQUIDEZ
      ------------------------- */

      case "liquidity":
        return json(
          res,
          200,
          {
            success: true,
            ...(await realLiquidity())
          }
        );

      /* -------------------------
         TRON USDT
      ------------------------- */

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

      /* -------------------------
         TRON TRX
      ------------------------- */

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

      /* -------------------------
         OPERAÇÕES
      ------------------------- */

      case "operations":
      case "transactions":
        return json(
          res,
          200,
          await operations()
        );

      /* -------------------------
         PAY STATUS
      ------------------------- */

      case "pay_status":
        return json(
          res,
          200,
          {
            success: true,
            configured:
              payConfigured()
          }
        );

      /* -------------------------
         HEALTH
      ------------------------- */

      case "health":
        return json(
          res,
          200,
          {
            success: true,
            api: "API06",
            service:
              "USDTMZ CENTRAL ADMIN",
            database: true,
            pay:
              payConfigured(),
            timestamp:
              new Date().toISOString()
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
            api: "API06"
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
