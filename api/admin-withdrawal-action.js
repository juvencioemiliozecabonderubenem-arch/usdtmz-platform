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

const TRON_HOST = "https://api.trongrid.io";
const TRON_FEE_LIMIT = 100_000_000;

const PAGAR_BASE_URL =
  process.env.PAGAR_API_BASE_URL ||
  "https://api.pagar.co.mz/api/v1";

const PAGAR_TIMEOUT = 10000;

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

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

function safeCompare(a, b) {
  if (!a || !b) return false;

  const aa = Buffer.from(String(a));
  const bb = Buffer.from(String(b));

  if (aa.length !== bb.length) return false;

  return timingSafeEqual(aa, bb);
}

function parseCookies(cookieHeader = "") {
  const cookies = {};

  for (const part of cookieHeader.split(";")) {
    const index = part.indexOf("=");

    if (index === -1) continue;

    const key = part.slice(0, index).trim();
    const value = part.slice(index + 1).trim();

    cookies[key] = decodeURIComponent(value);
  }

  return cookies;
}

function verifyAdminSession(token) {
  try {
    const secret = process.env.ADMIN_SESSION_SECRET;

    if (!secret || !token) return null;

    const parts = String(token).split(".");

    if (parts.length !== 2) return null;

    const [payload, signature] = parts;

    const expected = createHmac("sha256", secret)
      .update(payload)
      .digest("base64url");

    if (!safeCompare(signature, expected)) {
      return null;
    }

    const decoded = Buffer.from(payload, "base64url").toString("utf8");
    const data = JSON.parse(decoded);

    if (data?.id !== "admin") return null;
    if (!data?.email) return null;
    if (!Number.isFinite(Number(data?.exp))) return null;

    if (Date.now() >= Number(data.exp)) {
      return null;
    }

    return data;
  } catch {
    return null;
  }
}

function requireAdmin(req) {
  const cookies = parseCookies(req.headers.cookie || "");
  const session = verifyAdminSession(cookies[COOKIE_NAME]);

  if (!session) {
    const error = new Error("Não autorizado.");
    error.statusCode = 401;
    throw error;
  }

  return session;
}

function makeReference(prefix = "TREASURY") {
  const random = randomBytes(8).toString("hex").toUpperCase();

  return `${prefix}-${Date.now()}-${random}`;
}

function normalizeSource(source) {
  return String(source || "")
    .trim()
    .toUpperCase();
}

function isValidSource(source) {
  return SOURCES.includes(normalizeSource(source));
}

function positiveNumber(value) {
  const number = Number(value);

  if (!Number.isFinite(number) || number <= 0) {
    return null;
  }

  return number;
}

function roundMoney(value, decimals = 6) {
  const factor = 10 ** decimals;

  return Math.round((Number(value) + Number.EPSILON) * factor) / factor;
}

function validTronAddress(address) {
  try {
    return Boolean(
      address &&
      TronWeb.isAddress(String(address).trim())
    );
  } catch {
    return false;
  }
}

function normalizeTronAddress(address) {
  return String(address || "").trim();
}

function normalizeMozPhone(phone) {
  let value = String(phone || "")
    .replace(/\s+/g, "")
    .replace(/-/g, "");

  if (value.startsWith("+258")) {
    value = value.slice(4);
  }

  if (value.startsWith("258")) {
    value = value.slice(3);
  }

  if (!/^(8[2-7])\d{7}$/.test(value)) {
    return null;
  }

  return value;
}

function normalizePagarMethod(method) {
  const value = String(method || "")
    .trim()
    .toUpperCase();

  if (value === "M-PESA" || value === "MPESA") {
    return "MPESA";
  }

  if (
    value === "E-MOLA" ||
    value === "EMOLA" ||
    value === "E MOLA"
  ) {
    return "EMOLA";
  }

  return null;
}

function getTreasuryAddress() {
  const address = normalizeTronAddress(
    process.env.USDTMZ_TRON_WALLET_ADDRESS
  );

  if (!address || !validTronAddress(address)) {
    throw new Error(
      "USDTMZ_TRON_WALLET_ADDRESS não está configurado corretamente."
    );
  }

  return address;
}

function getTronWeb() {
  const apiKey = process.env.TRON_PRO_API_KEY;

  if (!apiKey) {
    throw new Error("TRON_PRO_API_KEY não configurado.");
  }

  return new TronWeb({
    fullHost: TRON_HOST,
    headers: {
      "TRON-PRO-API-KEY": apiKey
    }
  });
}

async function fetchJson(url, options = {}, timeoutMs = 8000) {
  const controller = new AbortController();

  const timer = setTimeout(() => {
    controller.abort();
  }, timeoutMs);

  try {
    const response = await fetch(url, {
      ...options,
      signal: controller.signal
    });

    const text = await response.text();

    let data = null;

    try {
      data = text ? JSON.parse(text) : null;
    } catch {
      data = text;
    }

    if (!response.ok) {
      const message =
        data?.message ||
        data?.error ||
        `HTTP ${response.status}`;

      const error = new Error(message);
      error.statusCode = response.status;
      error.data = data;

      throw error;
    }

    return data;
  } finally {
    clearTimeout(timer);
  }
}

/* ============================================================
   AFRICA API
============================================================ */

async function getUsdMznFromAfricaApi() {
  const apiKey = process.env.AFRICA_API_KEY;

  if (!apiKey) {
    throw new Error("AFRICA_API_KEY não configurado.");
  }

  const url =
    "https://api.africa-api.com/v1/data" +
    "?country_code=MZ" +
    "&metric_key=official_exchange_rate_latest_lcu_per_usd" +
    "&latest=true";

  const data = await fetchJson(
    url,
    {
      headers: {
        Authorization: `Bearer ${apiKey}`,
        Accept: "application/json"
      }
    },
    8000
  );

  const rows = Array.isArray(data?.data)
    ? data.data
    : [];

  const row = rows.find((item) => {
    const country = String(
      item?.country_code || ""
    ).toUpperCase();

    const value = Number(item?.value);

    return (
      country === "MZ" &&
      Number.isFinite(value) &&
      value > 0
    );
  });

  if (!row) {
    throw new Error(
      "Africa API não devolveu uma taxa USD/MZN válida."
    );
  }

  return {
    rate: Number(row.value),
    source: "AFRICA_API"
  };
}

/* ============================================================
   AFRIRATE
============================================================ */

async function getUsdMznFromAfriRate() {
  const url =
    "https://afrirate.com/api/v1/rates/latest?country=MZ";

  const data = await fetchJson(
    url,
    {
      headers: {
        Accept: "application/json"
      }
    },
    8000
  );

  const directCandidates = [
    data?.rate,
    data?.data?.rate,
    data?.data?.usd_mzn,
    data?.data?.USD_MZN,
    data?.usd_mzn,
    data?.USD_MZN,
    data?.rates?.USD_MZN,
    data?.rates?.["USD/MZN"],
    data?.rates?.USD?.MZN
  ];

  for (const candidate of directCandidates) {
    const value = Number(candidate);

    if (Number.isFinite(value) && value > 0) {
      return {
        rate: value,
        source: "AFRIRATE"
      };
    }
  }

  const arrays = [
    data?.data,
    data?.rates
  ];

  for (const array of arrays) {
    if (!Array.isArray(array)) continue;

    for (const item of array) {
      const pair = String(
        item?.pair ||
        item?.symbol ||
        item?.currency ||
        item?.code ||
        ""
      )
        .replace(/\s+/g, "")
        .toUpperCase();

      const value = Number(
        item?.rate ??
        item?.value ??
        item?.price
      );

      if (
        (pair === "USD/MZN" ||
          pair === "USDMZN") &&
        Number.isFinite(value) &&
        value > 0
      ) {
        return {
          rate: value,
          source: "AFRIRATE"
        };
      }
    }
  }

  throw new Error(
    "AfriRate não devolveu uma taxa USD/MZN válida."
  );
}

/* ============================================================
   MONEYCONVERT
============================================================ */

async function getUsdMznFromMoneyConvert() {
  const url =
    "https://cdn.moneyconvert.net/api/latest.json";

  const data = await fetchJson(
    url,
    {
      headers: {
        Accept: "application/json"
      }
    },
    8000
  );

  const value = Number(data?.rates?.MZN);

  if (!Number.isFinite(value) || value <= 0) {
    throw new Error(
      "MoneyConvert não devolveu uma taxa USD/MZN válida."
    );
  }

  return {
    rate: value,
    source: "MONEYCONVERT"
  };
}

async function getUsdMzn() {
  try {
    return await getUsdMznFromAfricaApi();
  } catch {}

  try {
    return await getUsdMznFromAfriRate();
  } catch {}

  return await getUsdMznFromMoneyConvert();
}

/* ============================================================
   USDT / USD
============================================================ */

async function getUsdtUsdFromCoinbase() {
  const url =
    "https://api.coinbase.com/v2/exchange-rates?currency=USDT";

  const data = await fetchJson(
    url,
    {
      headers: {
        Accept: "application/json"
      }
    },
    8000
  );

  const value = Number(
    data?.data?.rates?.USD
  );

  if (!Number.isFinite(value) || value <= 0) {
    throw new Error(
      "Coinbase não devolveu USDT/USD válido."
    );
  }

  return {
    rate: value,
    source: "COINBASE"
  };
}

async function getUsdtUsdFromCoinGecko() {
  const url =
    "https://api.coingecko.com/api/v3/simple/price?ids=tether&vs_currencies=usd";

  const data = await fetchJson(
    url,
    {
      headers: {
        Accept: "application/json"
      }
    },
    8000
  );

  const value = Number(
    data?.tether?.usd
  );

  if (!Number.isFinite(value) || value <= 0) {
    throw new Error(
      "CoinGecko não devolveu USDT/USD válido."
    );
  }

  return {
    rate: value,
    source: "COINGECKO"
  };
}

async function getUsdtUsd() {
  try {
    return await getUsdtUsdFromCoinbase();
  } catch {}

  return await getUsdtUsdFromCoinGecko();
}

/* ============================================================
   REAL USDT/MZN RATE
============================================================ */

let rateCache = {
  value: null,
  marketRate: null,
  usdMzn: null,
  usdtUsd: null,
  spreadPercent: RATE_SPREAD_PERCENT,
  source: null,
  updatedAt: null
};

let ratePromise = null;

async function getRealUsdtMznRate(force = false) {
  const now = Date.now();

  if (
    !force &&
    rateCache.value &&
    rateCache.updatedAt &&
    now - new Date(rateCache.updatedAt).getTime() < 60000
  ) {
    return rateCache;
  }

  if (ratePromise) {
    return ratePromise;
  }

  ratePromise = (async () => {
    const [usdMzn, usdtUsd] = await Promise.all([
      getUsdMzn(),
      getUsdtUsd()
    ]);

    const marketRate =
      Number(usdMzn.rate) *
      Number(usdtUsd.rate);

    if (
      !Number.isFinite(marketRate) ||
      marketRate <= 0
    ) {
      throw new Error(
        "Não foi possível calcular a taxa real USDT/MZN."
      );
    }

    const spread =
      Number.isFinite(RATE_SPREAD_PERCENT) &&
      RATE_SPREAD_PERCENT >= 0
        ? RATE_SPREAD_PERCENT
        : 0;

    const sellRate =
      marketRate *
      (1 + spread / 100);

    rateCache = {
      value: roundMoney(sellRate, 6),
      marketRate: roundMoney(marketRate, 6),
      usdMzn: {
        rate: roundMoney(usdMzn.rate, 6),
        source: usdMzn.source
      },
      usdtUsd: {
        rate: roundMoney(usdtUsd.rate, 8),
        source: usdtUsd.source
      },
      spreadPercent: spread,
      source:
        `${usdMzn.source}+${usdtUsd.source}`,
      updatedAt: new Date().toISOString()
    };

    return rateCache;
  })();

  try {
    return await ratePromise;
  } finally {
    ratePromise = null;
  }
}

/* ============================================================
   TRON
============================================================ */

function topicToAddress(topic) {
  if (!topic) return null;

  const clean = String(topic)
    .replace(/^0x/, "")
    .padStart(64, "0");

  if (!/^[0-9a-fA-F]{64}$/.test(clean)) {
    return null;
  }

  try {
    return TronWeb.address.fromHex(
      `41${clean.slice(-40)}`
    );
  } catch {
    return null;
  }
}

function topicToAmount(topic) {
  if (!topic) return 0;

  const clean = String(topic)
    .replace(/^0x/, "");

  try {
    return Number(
      BigInt(`0x${clean}`)
    ) / 10 ** USDT_DECIMALS;
  } catch {
    return 0;
  }
}

async function getTransactionInfo(txHash) {
  const apiKey = process.env.TRON_PRO_API_KEY;

  if (!apiKey) {
    throw new Error(
      "TRON_PRO_API_KEY não configurado."
    );
  }

  return await fetchJson(
    `${TRON_HOST}/wallet/gettransactioninfobyid`,
    {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "TRON-PRO-API-KEY": apiKey
      },
      body: JSON.stringify({
        value: txHash
      })
    },
    10000
  );
}

async function verifyUsdtTransfer(
  txHash,
  requestedAmount = 0
) {
  const treasuryAddress =
    getTreasuryAddress();

  if (
    !txHash ||
    !/^[a-fA-F0-9]{64}$/.test(String(txHash))
  ) {
    return {
      confirmed: false,
      pending: false,
      failed: true,
      reason: "TX_HASH_INVALID"
    };
  }

  let info;

  try {
    info = await getTransactionInfo(
      String(txHash)
    );
  } catch {
    return {
      confirmed: false,
      pending: true,
      failed: false,
      reason: "TX_NOT_INDEXED"
    };
  }

  const receipt =
    info?.receipt ||
    {};

  const result =
    String(receipt.result || "")
      .toUpperCase();

  if (
    result === "FAILED" ||
    result === "OUT_OF_TIME" ||
    result === "OUT_OF_ENERGY"
  ) {
    return {
      confirmed: false,
      pending: false,
      failed: true,
      reason: result
    };
  }

  if (
    !info ||
    !info.id
  ) {
    return {
      confirmed: false,
      pending: true,
      failed: false,
      reason: "PENDING"
    };
  }

  const apiKey =
    process.env.TRON_PRO_API_KEY;

  const eventsUrl =
    `${TRON_HOST}/v1/transactions/${encodeURIComponent(
      txHash
    )}/events?only_confirmed=true&limit=200`;

  let eventsData;

  try {
    eventsData = await fetchJson(
      eventsUrl,
      {
        headers: {
          Accept: "application/json",
          "TRON-PRO-API-KEY": apiKey
        }
      },
      10000
    );
  } catch {
    return {
      confirmed: false,
      pending: true,
      failed: false,
      reason: "EVENTS_PENDING"
    };
  }

  const events = Array.isArray(
    eventsData?.data
  )
    ? eventsData.data
    : [];

  let received = 0;
  let matched = false;

  for (const event of events) {
    const eventName =
      String(event?.event_name || "")
        .toLowerCase();

    const contract =
      String(
        event?.address ||
        event?.contract_address ||
        ""
      );

    if (
      eventName !== "transfer" ||
      contract.toLowerCase() !==
        USDT_CONTRACT.toLowerCase()
    ) {
      continue;
    }

    const result = event?.result || {};

    const from =
      topicToAddress(
        result.from ||
        event?.topics?.[1]
      );

    const to =
      topicToAddress(
        result.to ||
        event?.topics?.[2]
      );

    const amount =
      Number(
        result.value ??
        event?.data ??
        topicToAmount(
          event?.topics?.[3]
        )
      );

    if (
      to &&
      to.toLowerCase() ===
        treasuryAddress.toLowerCase()
    ) {
      matched = true;
      received += Number.isFinite(amount)
        ? amount
        : 0;
    }
  }

  if (!matched || received <= 0) {
    return {
      confirmed: false,
      pending: true,
      failed: false,
      reason: "TRANSFER_NOT_FOUND",
      received: 0
    };
  }

  if (
    requestedAmount > 0 &&
    received + 0.000001 <
      Number(requestedAmount)
  ) {
    return {
      confirmed: false,
      pending: false,
      failed: true,
      reason: "AMOUNT_TOO_LOW",
      received
    };
  }

  return {
    confirmed: true,
    pending: false,
    failed: false,
    received: roundMoney(received, 6),
    txHash
  };
}

/* ============================================================
   PAGAR
============================================================ */

function requirePagarConfig() {
  const apiKey =
    process.env.PAGAR_API_KEY;

  const signingSecret =
    process.env.PAGAR_SIGNING_SECRET;

  if (!apiKey) {
    throw new Error(
      "PAGAR_API_KEY não configurado."
    );
  }

  if (!signingSecret) {
    throw new Error(
      "PAGAR_SIGNING_SECRET não configurado."
    );
  }

  return {
    apiKey,
    signingSecret
  };
}

function pagarCanonicalPath(path) {
  const cleanBase =
    PAGAR_BASE_URL.replace(/\/+$/, "");

  const baseUrl =
    new URL(cleanBase);

  const normalizedPath =
    String(path).startsWith("/")
      ? String(path)
      : `/${path}`;

  return `${baseUrl.pathname.replace(/\/+$/, "")}${normalizedPath}`;
}

function signPagarRequest({
  timestamp,
  nonce,
  method,
  path,
  body
}) {
  const {
    signingSecret
  } = requirePagarConfig();

  const rawBody =
    body == null
      ? ""
      : JSON.stringify(body);

  const bodyHash =
    createHmac("sha256", "")
      .update(rawBody)
      .digest("hex");

  const canonical = [
    timestamp,
    nonce,
    method.toUpperCase(),
    pagarCanonicalPath(path),
    bodyHash
  ].join("\n");

  return createHmac(
    "sha256",
    signingSecret
  )
    .update(canonical)
    .digest("hex");
}

async function pagarRequest(
  method,
  path,
  body = null,
  options = {}
) {
  const {
    apiKey
  } = requirePagarConfig();

  const timestamp =
    String(Math.floor(Date.now() / 1000));

  const nonce =
    randomBytes(16).toString("hex");

  const signature =
    signPagarRequest({
      timestamp,
      nonce,
      method,
      path,
      body
    });

  const headers = {
    Authorization:
      `Bearer ${apiKey}`,
    Accept: "application/json",
    "X-Pagar-Timestamp":
      timestamp,
    "X-Pagar-Nonce":
      nonce,
    "X-Pagar-Signature":
      `v1=${signature}`
  };

  if (body !== null) {
    headers["Content-Type"] =
      "application/json";
  }

  if (options.idempotencyKey) {
    headers["Idempotency-Key"] =
      options.idempotencyKey;
  }

  const url =
    `${PAGAR_BASE_URL.replace(/\/+$/, "")}${path}`;

  return await fetchJson(
    url,
    {
      method,
      headers,
      ...(body !== null
        ? {
            body: JSON.stringify(body)
          }
        : {})
    },
    PAGAR_TIMEOUT
  );
}

async function createPagarTreasuryTopup(body) {
  const amount =
    positiveNumber(body?.amount);

  if (
    !amount ||
    amount < MIN_MZN ||
    amount > MAX_MZN
  ) {
    throw new Error(
      `O valor deve estar entre ${MIN_MZN} e ${MAX_MZN} MZN.`
    );
  }

  const method =
    normalizePagarMethod(
      body?.method
    );

  if (!method) {
    throw new Error(
      "Método Pagar inválido. Use MPESA ou EMOLA."
    );
  }

  const phone =
    normalizeMozPhone(
      body?.payment_phone ||
      body?.phone
    );

  if (!phone) {
    throw new Error(
      "Número de telefone M-Pesa/e-Mola inválido."
    );
  }

  const reference =
    String(
      body?.reference ||
      makeReference("TOPUP")
    )
      .trim();

  if (
    !/^[A-Za-z0-9._-]{6,120}$/.test(
      reference
    )
  ) {
    throw new Error(
      "Referência de top-up inválida."
    );
  }

  const payload = {
    reference,
    amountMzn: roundMoney(amount, 2),
    method,
    paymentPhone: phone
  };

  const data =
    await pagarRequest(
      "POST",
      "/wallet/topups",
      payload,
      {
        idempotencyKey:
          reference
      }
    );

  const pagarTopup =
    data?.data ||
    data?.topup ||
    data;

  const status =
    String(
      pagarTopup?.status ||
      "PENDING"
    ).toUpperCase();

  const pagarId =
    pagarTopup?.id ||
    pagarTopup?.topupId ||
    pagarTopup?.paymentId ||
    null;

  const existing =
    await sql`
      SELECT id, amount, status, reference
      FROM transactions
      WHERE reference = ${reference}
      LIMIT 1
    `;

  if (existing.length === 0) {
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
        'admin',
        'DEPOSIT_MZN',
        'MZN',
        ${roundMoney(amount, 2)},
        ${status === "PAID"
          ? "COMPLETED"
          : "PENDING"},
        ${reference},
        NULL,
        NOW()
      )
    `;
  }

  if (status === "PAID") {
    await confirmPagarTreasuryTopup({
      reference
    });
  }

  return {
    success: true,
    reference,
    amountMzn: roundMoney(amount, 2),
    method,
    paymentPhone: phone,
    status,
    pagarId,
    data
  };
}

async function getPagarTopupByReference(
  reference
) {
  const cleanReference =
    String(reference || "").trim();

  if (!cleanReference) {
    throw new Error(
      "Referência do top-up obrigatória."
    );
  }

  return await pagarRequest(
    "GET",
    `/wallet/topups/by-reference/${encodeURIComponent(
      cleanReference
    )}`,
    null
  );
}

async function confirmPagarTreasuryTopup(
  body
) {
  const reference =
    String(body?.reference || "").trim();

  if (!reference) {
    throw new Error(
      "Referência do top-up obrigatória."
    );
  }

  const pagarResponse =
    await getPagarTopupByReference(
      reference
    );

  const pagarTopup =
    pagarResponse?.data ||
    pagarResponse?.topup ||
    pagarResponse;

  const pagarStatus =
    String(
      pagarTopup?.status ||
      ""
    ).toUpperCase();

  const rows =
    await sql`
      SELECT
        id,
        amount,
        status,
        reference
      FROM transactions
      WHERE reference = ${reference}
        AND type = 'DEPOSIT_MZN'
      LIMIT 1
    `;

  if (rows.length === 0) {
    throw new Error(
      "Top-up não encontrado na tesouraria."
    );
  }

  const transaction =
    rows[0];

  if (
    String(transaction.status).toUpperCase() ===
    "COMPLETED"
  ) {
    return {
      success: true,
      alreadyCompleted: true,
      reference,
      status: "COMPLETED",
      amountMzn:
        Number(transaction.amount)
    };
  }

  if (
    pagarStatus !== "PAID" &&
    pagarStatus !== "SUCCEEDED" &&
    pagarStatus !== "SUCCESS"
  ) {
    const localStatus =
      pagarStatus === "FAILED" ||
      pagarStatus === "CANCELLED"
        ? "FAILED"
        : "PENDING";

    await sql`
      UPDATE transactions
      SET status = ${localStatus}
      WHERE id = ${transaction.id}
        AND status <> 'COMPLETED'
    `;

    return {
      success: true,
      alreadyCompleted: false,
      reference,
      status: localStatus,
      pagarStatus,
      amountMzn:
        Number(transaction.amount)
    };
  }

  const amount =
    Number(transaction.amount);

  if (
    !Number.isFinite(amount) ||
    amount <= 0
  ) {
    throw new Error(
      "Valor do top-up inválido."
    );
  }

  const wallets =
    await sql`
      SELECT id, balance
      FROM wallets
      WHERE asset = 'MZN'
      ORDER BY id ASC
      LIMIT 1
      FOR UPDATE
    `;

  if (wallets.length === 0) {
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
        NULL,
        'MZN',
        'MZN',
        ${roundMoney(amount, 2)},
        'ACTIVE',
        NOW(),
        NOW(),
        NULL
      )
    `;
  } else {
    const wallet =
      wallets[0];

    const current =
      Number(wallet.balance || 0);

    await sql`
      UPDATE wallets
      SET
        balance = ${roundMoney(
          current + amount,
          2
        )},
        updated_at = NOW(),
        status = 'ACTIVE'
      WHERE id = ${wallet.id}
    `;
  }

  await sql`
    UPDATE transactions
    SET status = 'COMPLETED'
    WHERE id = ${transaction.id}
      AND status <> 'COMPLETED'
  `;

  return {
    success: true,
    alreadyCompleted: false,
    reference,
    status: "COMPLETED",
    pagarStatus,
    amountMzn: roundMoney(amount, 2),
    pagarId:
      pagarTopup?.id ||
      pagarTopup?.topupId ||
      pagarTopup?.paymentId ||
      null
  };
}

/* ============================================================
   WALLETS
============================================================ */

async function getOrCreateWallet(asset) {
  const normalized =
    String(asset || "")
      .trim()
      .toUpperCase();

  const rows =
    await sql`
      SELECT *
      FROM wallets
      WHERE asset = ${normalized}
      ORDER BY id ASC
      LIMIT 1
    `;

  if (rows.length > 0) {
    return rows[0];
  }

  if (normalized === "USDT") {
    const address =
      getTreasuryAddress();

    const inserted =
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

  const inserted =
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
        NULL,
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

/* ============================================================
   MZN DEPOSIT
============================================================ */

async function registerMZNDeposit(body) {
  const amount =
    positiveNumber(body?.amount);

  if (
    !amount ||
    amount < MIN_MZN ||
    amount > MAX_MZN
  ) {
    throw new Error(
      `O valor deve estar entre ${MIN_MZN} e ${MAX_MZN} MZN.`
    );
  }

  const source =
    normalizeSource(body?.source);

  if (!isValidSource(source)) {
    throw new Error(
      "Fonte de depósito inválida."
    );
  }

  if (
    source === "MPESA_BUSINESS" ||
    source === "EMOLA_BUSINESS"
  ) {
    return await createPagarTreasuryTopup({
      amount,
      method:
        source === "MPESA_BUSINESS"
          ? "MPESA"
          : "EMOLA",
      payment_phone:
        body?.payment_phone ||
        body?.phone,
      reference:
        body?.reference
    });
  }

  const reference =
    String(
      body?.reference ||
      makeReference("MZN")
    ).trim();

  const existing =
    await sql`
      SELECT *
      FROM transactions
      WHERE reference = ${reference}
      LIMIT 1
    `;

  if (existing.length > 0) {
    return {
      success: true,
      alreadyExists: true,
      transaction: existing[0]
    };
  }

  const inserted =
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
        'admin',
        'DEPOSIT_MZN',
        'MZN',
        ${roundMoney(amount, 2)},
        'PENDING',
        ${reference},
        NULL,
        NOW()
      )
      RETURNING *
    `;

  return {
    success: true,
    alreadyExists: false,
    transaction: inserted[0]
  };
}

async function confirmMZNDeposit(body) {
  const reference =
    String(body?.reference || "").trim();

  if (!reference) {
    throw new Error(
      "Referência obrigatória."
    );
  }

  const rows =
    await sql`
      SELECT *
      FROM transactions
      WHERE reference = ${reference}
        AND type = 'DEPOSIT_MZN'
        AND asset = 'MZN'
      LIMIT 1
    `;

  if (rows.length === 0) {
    throw new Error(
      "Depósito MZN não encontrado."
    );
  }

  const transaction =
    rows[0];

  if (
    String(transaction.status).toUpperCase() ===
    "COMPLETED"
  ) {
    return {
      success: true,
      alreadyCompleted: true,
      transaction
    };
  }

  const amount =
    Number(transaction.amount);

  if (
    !Number.isFinite(amount) ||
    amount <= 0
  ) {
    throw new Error(
      "Valor do depósito inválido."
    );
  }

  const wallet =
    await getOrCreateWallet("MZN");

  const current =
    Number(wallet.balance || 0);

  await sql`
    UPDATE wallets
    SET
      balance = ${roundMoney(
        current + amount,
        2
      )},
      updated_at = NOW(),
      status = 'ACTIVE'
    WHERE id = ${wallet.id}
  `;

  const updated =
    await sql`
      UPDATE transactions
      SET status = 'COMPLETED'
      WHERE id = ${transaction.id}
        AND status <> 'COMPLETED'
      RETURNING *
    `;

  return {
    success: true,
    alreadyCompleted: false,
    transaction:
      updated[0] || transaction
  };
}

/* ============================================================
   USDT DEPOSIT
============================================================ */

async function registerUSDTDeposit(body) {
  const amount =
    positiveNumber(body?.amount);

  const txHash =
    String(
      body?.tx_hash ||
      body?.blockchain_tx_hash ||
      ""
    ).trim();

  const source =
    normalizeSource(
      body?.source || "USDT_TRON"
    );

  if (source !== "USDT_TRON") {
    throw new Error(
      "Depósito USDT deve usar USDT_TRON."
    );
  }

  if (!amount) {
    throw new Error(
      "Quantidade USDT inválida."
    );
  }

  if (
    !/^[a-fA-F0-9]{64}$/.test(txHash)
  ) {
    throw new Error(
      "TX hash TRON inválido."
    );
  }

  const existing =
    await sql`
      SELECT *
      FROM transactions
      WHERE blockchain_tx_hash = ${txHash}
      LIMIT 1
    `;

  if (existing.length > 0) {
    return {
      success: true,
      alreadyExists: true,
      transaction: existing[0]
    };
  }

  const reference =
    String(
      body?.reference ||
      makeReference("USDT")
    ).trim();

  const inserted =
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
        'admin',
        'DEPOSIT_USDT',
        'USDT',
        ${roundMoney(amount, 6)},
        'PENDING',
        ${reference},
        ${txHash},
        NOW()
      )
      RETURNING *
    `;

  let verification;

  try {
    verification =
      await verifyUsdtTransfer(
        txHash,
        amount
      );
  } catch {
    verification = {
      confirmed: false,
      pending: true,
      failed: false
    };
  }

  if (verification.failed) {
    await sql`
      UPDATE transactions
      SET status = 'FAILED'
      WHERE id = ${inserted[0].id}
    `;

    return {
      success: false,
      status: "FAILED",
      verification
    };
  }

  if (!verification.confirmed) {
    return {
      success: true,
      status: "PENDING",
      verification,
      transaction: inserted[0]
    };
  }

  return await confirmUSDTDeposit({
    reference,
    tx_hash: txHash,
    amount:
      verification.received
  });
}

async function confirmUSDTDeposit(body) {
  const reference =
    String(body?.reference || "").trim();

  const txHash =
    String(
      body?.tx_hash ||
      body?.blockchain_tx_hash ||
      ""
    ).trim();

  if (!reference) {
    throw new Error(
      "Referência obrigatória."
    );
  }

  if (
    !/^[a-fA-F0-9]{64}$/.test(txHash)
  ) {
    throw new Error(
      "TX hash TRON inválido."
    );
  }

  const rows =
    await sql`
      SELECT *
      FROM transactions
      WHERE reference = ${reference}
        AND type = 'DEPOSIT_USDT'
      LIMIT 1
    `;

  if (rows.length === 0) {
    throw new Error(
      "Depósito USDT não encontrado."
    );
  }

  const transaction =
    rows[0];

  if (
    String(transaction.status).toUpperCase() ===
    "COMPLETED"
  ) {
    return {
      success: true,
      alreadyCompleted: true,
      transaction
    };
  }

  const requestedAmount =
    Number(
      body?.amount ||
      transaction.amount
    );

  const verification =
    await verifyUsdtTransfer(
      txHash,
      requestedAmount
    );

  if (verification.failed) {
    await sql`
      UPDATE transactions
      SET status = 'FAILED'
      WHERE id = ${transaction.id}
    `;

    return {
      success: false,
      status: "FAILED",
      verification
    };
  }

  if (!verification.confirmed) {
    return {
      success: true,
      status: "PENDING",
      verification
    };
  }

  const received =
    roundMoney(
      verification.received,
      6
    );

  const wallet =
    await getOrCreateWallet("USDT");

  const current =
    Number(wallet.balance || 0);

  await sql`
    UPDATE wallets
    SET
      balance = ${roundMoney(
        current + received,
        6
      )},
      updated_at = NOW(),
      status = 'ACTIVE'
    WHERE id = ${wallet.id}
  `;

  const updated =
    await sql`
      UPDATE transactions
      SET
        amount = ${received},
        status = 'COMPLETED',
        blockchain_tx_hash = ${txHash}
      WHERE id = ${transaction.id}
        AND status <> 'COMPLETED'
      RETURNING *
    `;

  return {
    success: true,
    alreadyCompleted: false,
    status: "COMPLETED",
    received,
    txHash,
    transaction:
      updated[0] || transaction
  };
}

/* ============================================================
   MZN -> USDT
============================================================ */

async function convertMZNToUSDT(body) {
  const amountMzn =
    positiveNumber(
      body?.amount_mzn ??
      body?.amount
    );

  if (
    !amountMzn ||
    amountMzn < MIN_MZN ||
    amountMzn > MAX_MZN
  ) {
    throw new Error(
      `O valor deve estar entre ${MIN_MZN} e ${MAX_MZN} MZN.`
    );
  }

  const rate =
    await getRealUsdtMznRate(true);

  const usdtAmount =
    roundMoney(
      amountMzn / rate.value,
      6
    );

  if (
    !Number.isFinite(usdtAmount) ||
    usdtAmount <= 0
  ) {
    throw new Error(
      "Quantidade USDT calculada inválida."
    );
  }

  const mznWallet =
    await getOrCreateWallet("MZN");

  const usdtWallet =
    await getOrCreateWallet("USDT");

  const mznBalance =
    Number(mznWallet.balance || 0);

  const usdtBalance =
    Number(usdtWallet.balance || 0);

  if (mznBalance < amountMzn) {
    throw new Error(
      "Saldo MZN insuficiente na tesouraria."
    );
  }

  if (usdtBalance < usdtAmount) {
    throw new Error(
      "Liquidez USDT insuficiente na tesouraria."
    );
  }

  const reference =
    String(
      body?.reference ||
      makeReference("CONV")
    ).trim();

  await sql`
    UPDATE wallets
    SET
      balance = ${roundMoney(
        mznBalance - amountMzn,
        2
      )},
      updated_at = NOW()
    WHERE id = ${mznWallet.id}
      AND balance >= ${amountMzn}
  `;

  const usdtUpdated =
    await sql`
      UPDATE wallets
      SET
        balance = ${roundMoney(
          usdtBalance - usdtAmount,
          6
        )},
        updated_at = NOW()
      WHERE id = ${usdtWallet.id}
        AND balance >= ${usdtAmount}
      RETURNING id
    `;

  if (usdtUpdated.length === 0) {
    await sql`
      UPDATE wallets
      SET
        balance = ${roundMoney(
          mznBalance,
          2
        )},
        updated_at = NOW()
      WHERE id = ${mznWallet.id}
    `;

    throw new Error(
      "Não foi possível reservar USDT."
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
      blockchain_tx_hash,
      created_at
    )
    VALUES
    (
      'admin',
      'CONVERSION',
      'USDT',
      ${usdtAmount},
      'COMPLETED',
      ${reference},
      NULL,
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
      blockchain_tx_hash,
      created_at
    )
    VALUES
    (
      'admin',
      'RESERVE_IN',
      'USDT',
      ${usdtAmount},
      'RESERVED',
      ${reference},
      NULL,
      NOW()
    )
  `;

  return {
    success: true,
    reference,
    amountMzn:
      roundMoney(amountMzn, 2),
    usdtAmount,
    rate: rate.value,
    marketRate: rate.marketRate,
    rateSource: rate.source,
    updatedAt: rate.updatedAt
  };
}

/* ============================================================
   RELEASE RESERVATION
============================================================ */

async function releaseReservation(body) {
  const reference =
    String(body?.reference || "").trim();

  if (!reference) {
    throw new Error(
      "Referência obrigatória."
    );
  }

  const rows =
    await sql`
      SELECT *
      FROM transactions
      WHERE reference = ${reference}
        AND type = 'RESERVE_IN'
      LIMIT 1
    `;

  if (rows.length === 0) {
    throw new Error(
      "Reserva não encontrada."
    );
  }

  const reservation =
    rows[0];

  if (
    String(reservation.status).toUpperCase() ===
    "COMPLETED"
  ) {
    return {
      success: true,
      alreadyReleased: true,
      reservation
    };
  }

  if (
    String(reservation.status).toUpperCase() !==
    "RESERVED"
  ) {
    throw new Error(
      "Reserva não está ativa."
    );
  }

  const amount =
    Number(reservation.amount);

  const wallet =
    await getOrCreateWallet("USDT");

  const current =
    Number(wallet.balance || 0);

  await sql`
    UPDATE wallets
    SET
      balance = ${roundMoney(
        current + amount,
        6
      )},
      updated_at = NOW()
    WHERE id = ${wallet.id}
  `;

  const updated =
    await sql`
      UPDATE transactions
      SET status = 'COMPLETED'
      WHERE id = ${reservation.id}
        AND status = 'RESERVED'
      RETURNING *
    `;

  return {
    success: true,
    alreadyReleased: false,
    reservation:
      updated[0] || reservation
  };
}

/* ============================================================
   LIQUIDITY SOURCES
============================================================ */

function pagarConfigured() {
  return Boolean(
    process.env.PAGAR_API_KEY &&
    process.env.PAGAR_SIGNING_SECRET &&
    process.env.PAGAR_WEBHOOK_SECRET
  );
}

async function getLiquiditySources() {
  let realRate = null;

  try {
    realRate =
      await getRealUsdtMznRate(false);
  } catch {}

  const treasuryAddress =
    (() => {
      try {
        return getTreasuryAddress();
      } catch {
        return null;
      }
    })();

  const pagar =
    pagarConfigured();

  return [
    {
      source: "MPESA_BUSINESS",
      name: "M-Pesa",
      provider: "Pagar",
      configured: pagar,
      active: pagar,
      method: "MPESA"
    },
    {
      source: "EMOLA_BUSINESS",
      name: "e-Mola",
      provider: "Pagar",
      configured: pagar,
      active: pagar,
      method: "EMOLA"
    },
    {
      source: "BANK",
      name: "Banco",
      provider: "Manual",
      configured: true,
      active: false
    },
    {
      source: "USDT_TRON",
      name: "USDT TRC20",
      provider: "TRON",
      configured: Boolean(
        treasuryAddress
      ),
      active: Boolean(
        treasuryAddress
      )
    },
    {
      source: "EXTERNAL_WALLET",
      name: "Carteira externa",
      provider: "Manual",
      configured: true,
      active: false
    },
    {
      source: "USDT_PURCHASE",
      name: "Compra USDT",
      provider: "Tesouraria",
      configured: true,
      active: true
    },
    {
      source: "LIQUIDITY_PARTNER",
      name: "Parceiro de liquidez",
      provider: "External",
      configured: false,
      active: false
    },
    {
      source: "MANUAL_APPROVED",
      name: "Manual aprovado",
      provider: "Admin",
      configured: true,
      active: true
    },
    {
      source: "REAL_FX_RATE",
      name: "Taxa real MZN/USDT",
      provider:
        realRate?.source || null,
      configured: Boolean(realRate),
      active: Boolean(realRate),
      rate:
        realRate?.value || null,
      marketRate:
        realRate?.marketRate || null,
      updatedAt:
        realRate?.updatedAt || null
    }
  ];
}

/* ============================================================
   DASHBOARD
============================================================ */

async function getDashboard() {
  const mznWallet =
    await getOrCreateWallet("MZN");

  const usdtWallet =
    await getOrCreateWallet("USDT");

  const rate =
    await getRealUsdtMznRate(false)
      .catch(() => null);

  const [
    pendingDeposits,
    orders,
    withdrawals,
    transactions,
    binanceTransfers
  ] = await Promise.all([
    sql`
      SELECT *
      FROM transactions
      WHERE status IN ('PENDING', 'PROCESSING')
      ORDER BY created_at DESC
      LIMIT 100
    `,

    sql`
      SELECT *
      FROM orders
      ORDER BY created_at DESC
      LIMIT 100
    `,

    sql`
      SELECT *
      FROM withdrawals
      ORDER BY created_at DESC
      LIMIT 100
    `,

    sql`
      SELECT *
      FROM transactions
      ORDER BY created_at DESC
      LIMIT 200
    `,

    sql`
      SELECT *
      FROM transactions
      WHERE type IN
      (
        'BINANCE_TRANSFER',
        'USDT_BINANCE',
        'BINANCE'
      )
      ORDER BY created_at DESC
      LIMIT 100
    `
  ]);

  const mznBalance =
    Number(mznWallet.balance || 0);

  const usdtBalance =
    Number(usdtWallet.balance || 0);

  let reservedUsdt = 0;

  try {
    const reserved =
      await sql`
        SELECT COALESCE(
          SUM(amount),
          0
        ) AS total
        FROM transactions
        WHERE type = 'RESERVE_IN'
          AND status = 'RESERVED'
      `;

    reservedUsdt =
      Number(
        reserved[0]?.total || 0
      );
  } catch {}

  const availableUsdt =
    Math.max(
      0,
      usdtBalance - reservedUsdt
    );

  return {
    treasury: {
      mzn: roundMoney(
        mznBalance,
        2
      ),
      usdt: roundMoney(
