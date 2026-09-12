import { neon } from "@neondatabase/serverless";
import { createHmac, timingSafeEqual, randomBytes } from "node:crypto";
import { TronWeb } from "tronweb";

const sql = neon(process.env.DATABASE_URL);

const COOKIE_NAME = "usdtmz_admin_session";

const MIN_MZN = 64;
const MAX_MZN = 40000;

const USDT_CONTRACT =
  process.env.USDT_TRON_CONTRACT ||
  "TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t";

const USDT_DECIMALS = 6;

/*
 * TAXA DE VENDA / SPREAD
 *
 * 0 = apenas taxa de referência.
 *
 * Exemplo:
 * USDTMZ_RATE_SPREAD_PERCENT=2
 *
 * Se a taxa de mercado for 63.90 MZN,
 * a taxa usada para vender USDT será aproximadamente:
 *
 * 63.90 × 1.02 = 65.178 MZN
 *
 * Por segurança, o padrão é 0.
 */
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
  "MANUAL_APPROVED"
];

/* =========================================================
   ADMIN SESSION
========================================================= */

function safeCompare(a, b) {
  const A = Buffer.from(String(a));
  const B = Buffer.from(String(b));

  if (A.length !== B.length) return false;

  return timingSafeEqual(A, B);
}

function parseCookies(req) {
  const header = req.headers?.cookie || "";
  const cookies = {};

  for (const part of header.split(";")) {
    const index = part.indexOf("=");

    if (index === -1) continue;

    const key = part.slice(0, index).trim();
    const value = part.slice(index + 1).trim();

    try {
      cookies[key] = decodeURIComponent(value);
    } catch {
      cookies[key] = value;
    }
  }

  return cookies;
}

function verifyAdminSession(req) {
  const secret = process.env.ADMIN_SESSION_SECRET;

  if (!secret) return null;

  const cookies = parseCookies(req);
  const token = cookies[COOKIE_NAME];

  if (!token) return null;

  const parts = token.split(".");

  if (parts.length !== 2) return null;

  const [data, signature] = parts;

  try {
    const expected = createHmac("sha256", secret)
      .update(data)
      .digest("base64url");

    if (!safeCompare(signature, expected)) {
      return null;
    }

    const payload = JSON.parse(
      Buffer.from(data, "base64url").toString("utf8")
    );

    if (payload.id !== "admin") return null;
    if (!payload.email) return null;

    if (!payload.exp || Date.now() >= Number(payload.exp)) {
      return null;
    }

    return payload;
  } catch {
    return null;
  }
}

function requireAdmin(req, res) {
  const session = verifyAdminSession(req);

  if (!session) {
    res.status(401).json({
      success: false,
      message: "Sessão administrativa inválida ou expirada."
    });

    return null;
  }

  return session;
}

/* =========================================================
   UTILITÁRIOS
========================================================= */

function makeReference(prefix = "TREASURY") {
  return `${prefix}-${Date.now()}-${randomBytes(5).toString("hex")}`;
}

function normalizeSource(source) {
  return String(source || "")
    .trim()
    .toUpperCase();
}

function isValidSource(source) {
  return SOURCES.includes(source);
}

function validTronAddress(address) {
  try {
    return TronWeb.isAddress(String(address || "").trim());
  } catch {
    return false;
  }
}

function getTreasuryAddress() {
  return String(
    process.env.USDTMZ_TRON_WALLET_ADDRESS || ""
  ).trim();
}

function getTronWeb() {
  const apiKey = process.env.TRON_PRO_API_KEY;

  const headers = apiKey
    ? {
        "TRON-PRO-API-KEY": apiKey
      }
    : {};

  return new TronWeb({
    fullHost: "https://api.trongrid.io",
    headers
  });
}

function roundMoney(value, decimals = 6) {
  const factor = 10 ** decimals;
  return Math.round(Number(value) * factor) / factor;
}

function positiveNumber(value) {
  const number = Number(value);

  return Number.isFinite(number) && number > 0
    ? number
    : null;
}

/* =========================================================
   MOTOR DE TAXA CAMBIAL REAL
========================================================= */

/*
 * A taxa USDT/MZN é calculada por:
 *
 * USD/MZN × USDT/USD
 *
 * Não usamos simplesmente "64" como verdade.
 *
 * Fontes:
 *
 * 1. AFRICA API, se AFRICA_API_KEY existir.
 * 2. AfriRate.
 * 3. MoneyConvert.
 *
 * USDT/USD:
 *
 * 1. Coinbase.
 * 2. CoinGecko.
 *
 * Se todas as fontes falharem, o sistema NÃO inventa uma taxa.
 */

let rateCache = {
  value: null,
  usdMzn: null,
  usdtUsd: null,
  source: null,
  updatedAt: 0
};

const RATE_CACHE_MS = 60 * 1000;

async function fetchJson(url, options = {}, timeoutMs = 8000) {
  const controller = new AbortController();

  const timeout = setTimeout(
    () => controller.abort(),
    timeoutMs
  );

  try {
    const response = await fetch(url, {
      ...options,
      signal: controller.signal
    });

    const text = await response.text();

    let data = null;

    try {
      data = JSON.parse(text);
    } catch {
      throw new Error(
        `Resposta JSON inválida do fornecedor (${response.status}).`
      );
    }

    if (!response.ok) {
      throw new Error(
        data?.message ||
        data?.error ||
        `Fornecedor respondeu HTTP ${response.status}.`
      );
    }

    return data;
  } finally {
    clearTimeout(timeout);
  }
}

async function getUsdMznFromAfricaApi() {
  const apiKey = process.env.AFRICA_API_KEY;

  if (!apiKey) {
    throw new Error("AFRICA_API_KEY não configurada.");
  }

  const data = await fetchJson(
    "https://api.africa-api.com/v1/data?country_code=MZ&metric_key=official_exchange_rate_latest_lcu_per_usd",
    {
      headers: {
        Authorization: `Bearer ${apiKey}`
      }
    }
  );

  const candidates = [
    data?.data?.value,
    data?.data?.rate,
    data?.value,
    data?.rate
  ];

  for (const candidate of candidates) {
    const rate = Number(candidate);

    if (Number.isFinite(rate) && rate > 0) {
      return {
        rate,
        source: "AFRICA_API"
      };
    }
  }

  throw new Error(
    "Africa API não devolveu USD/MZN válido."
  );
}

async function getUsdMznFromAfriRate() {
  const data = await fetchJson(
    "https://afrirate.statotec.com/api/rates",
    {},
    8000
  );

  /*
   * Aceita formatos comuns:
   *
   * {
   *   rates: {
   *      USD: {
   *        MZN: ...
   *      }
   *   }
   * }
   *
   * ou arrays.
   */

  const directCandidates = [
    data?.rates?.USD?.MZN,
    data?.rates?.MZN?.USD,
    data?.USD_MZN,
    data?.usd_mzn
  ];

  for (const candidate of directCandidates) {
    const rate = Number(candidate);

    if (Number.isFinite(rate) && rate > 0) {
      return {
        rate:
          data?.rates?.MZN?.USD
            ? 1 / rate
            : rate,
        source: "AFRIRATE"
      };
    }
  }

  if (Array.isArray(data)) {
    const item = data.find((entry) => {
      const pair = String(
        entry?.pair ||
        entry?.symbol ||
        entry?.currency ||
        ""
      )
        .replace(/[-_]/g, "/")
        .toUpperCase();

      return (
        pair === "USD/MZN" ||
        pair === "USD/MZN"
      );
    });

    const rate = Number(item?.rate);

    if (Number.isFinite(rate) && rate > 0) {
      return {
        rate,
        source: "AFRIRATE"
      };
    }
  }

  throw new Error(
    "AfriRate não devolveu USD/MZN válido."
  );
}

async function getUsdMznFromMoneyConvert() {
  const data = await fetchJson(
    "https://cdn.moneyconvert.net/api/latest.json",
    {},
    8000
  );

  const rate = Number(data?.rates?.MZN);

  if (!Number.isFinite(rate) || rate <= 0) {
    throw new Error(
      "MoneyConvert não devolveu MZN válido."
    );
  }

  return {
    rate,
    source: "MONEYCONVERT"
  };
}

async function getUsdMzn() {
  const errors = [];

  try {
    return await getUsdMznFromAfricaApi();
  } catch (error) {
    errors.push(`Africa API: ${error.message}`);
  }

  try {
    return await getUsdMznFromAfriRate();
  } catch (error) {
    errors.push(`AfriRate: ${error.message}`);
  }

  try {
    return await getUsdMznFromMoneyConvert();
  } catch (error) {
    errors.push(`MoneyConvert: ${error.message}`);
  }

  throw new Error(
    `Não foi possível obter USD/MZN em tempo real. ${errors.join(" | ")}`
  );
}

async function getUsdtUsdFromCoinbase() {
  const data = await fetchJson(
    "https://api.coinbase.com/v2/exchange-rates?currency=USDT",
    {},
    8000
  );

  const usd = Number(
    data?.data?.rates?.USD
  );

  if (!Number.isFinite(usd) || usd <= 0) {
    throw new Error(
      "Coinbase não devolveu USDT/USD válido."
    );
  }

  return {
    rate: usd,
    source: "COINBASE"
  };
}

async function getUsdtUsdFromCoinGecko() {
  const data = await fetchJson(
    "https://api.coingecko.com/api/v3/simple/price?ids=tether&vs_currencies=usd",
    {},
    8000
  );

  const usd = Number(
    data?.tether?.usd
  );

  if (!Number.isFinite(usd) || usd <= 0) {
    throw new Error(
      "CoinGecko não devolveu USDT/USD válido."
    );
  }

  return {
    rate: usd,
    source: "COINGECKO"
  };
}

async function getUsdtUsd() {
  const errors = [];

  try {
    return await getUsdtUsdFromCoinbase();
  } catch (error) {
    errors.push(`Coinbase: ${error.message}`);
  }

  try {
    return await getUsdtUsdFromCoinGecko();
  } catch (error) {
    errors.push(`CoinGecko: ${error.message}`);
  }

  throw new Error(
    `Não foi possível obter USDT/USD em tempo real. ${errors.join(" | ")}`
  );
}

async function getRealUsdtMznRate(force = false) {
  const now = Date.now();

  if (
    !force &&
    rateCache.value &&
    now - rateCache.updatedAt < RATE_CACHE_MS
  ) {
    return rateCache;
  }

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
      "Taxa USDT/MZN calculada é inválida."
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

  const result = {
    value: roundMoney(sellRate, 6),
    marketRate: roundMoney(marketRate, 6),
    usdMzn: roundMoney(usdMzn.rate, 6),
    usdtUsd: roundMoney(usdtUsd.rate, 8),
    spreadPercent: spread,
    source: `${usdMzn.source}+${usdtUsd.source}`,
    updatedAt: new Date().toISOString()
  };

  rateCache = {
    ...result,
    updatedAt: now
  };

  return rateCache;
}

/* =========================================================
   TRON
========================================================= */

function topicToAddress(topic) {
  const clean = String(topic || "")
    .replace(/^0x/, "");

  if (clean.length !== 64) return null;

  try {
    return TronWeb.address.fromHex(
      "41" + clean.slice(-40)
    );
  } catch {
    return null;
  }
}

function topicToAmount(data) {
  const clean = String(data || "")
    .replace(/^0x/, "");

  if (!clean) return 0;

  try {
    return Number(
      BigInt("0x" + clean)
    ) / 10 ** USDT_DECIMALS;
  } catch {
    return 0;
  }
}

async function getTransactionInfo(txHash) {
  const apiKey = process.env.TRON_PRO_API_KEY;

  if (!apiKey) {
    throw new Error(
      "TRON_PRO_API_KEY não configurada."
    );
  }

  const response = await fetch(
    `https://api.trongrid.io/wallet/gettransactioninfobyid?value=${encodeURIComponent(
      txHash
    )}`,
    {
      headers: {
        "TRON-PRO-API-KEY": apiKey
      }
    }
  );

  if (!response.ok) {
    throw new Error(
      "Falha ao consultar a blockchain TRON."
    );
  }

  return await response.json();
}

async function verifyUsdtTransfer(
  txHash,
  requestedAmount = 0
) {
  const treasuryAddress =
    getTreasuryAddress();

  if (!treasuryAddress) {
    return {
      confirmed: false,
      pending: false,
      reason:
        "Carteira Treasury não configurada."
    };
  }

  if (!validTronAddress(treasuryAddress)) {
    return {
      confirmed: false,
      pending: false,
      reason:
        "Endereço Treasury TRON inválido."
    };
  }

  const cleanHash =
    String(txHash || "").trim();

  if (
    !/^[a-fA-F0-9]{64}$/.test(cleanHash)
  ) {
    return {
      confirmed: false,
      pending: false,
      reason:
        "TX hash TRON inválido."
    };
  }

  let info;

  try {
    info =
      await getTransactionInfo(cleanHash);
  } catch (error) {
    return {
      confirmed: false,
      pending: true,
      reason: error.message
    };
  }

  if (!info || !info.id) {
    return {
      confirmed: false,
      pending: true,
      reason:
        "Transação ainda não encontrada na TRON."
    };
  }

  const receipt =
    info.receipt || {};

  const result =
    String(receipt.result || "")
      .toUpperCase();

  if (
    result &&
    result !== "SUCCESS"
  ) {
    return {
      confirmed: false,
      pending: false,
      reason:
        "Transação TRON falhou."
    };
  }

  /*
   * Procuramos somente eventos Transfer
   * do contrato oficial USDT TRC20.
   */
  let events = [];

  try {
    const apiKey =
      process.env.TRON_PRO_API_KEY;

    const response = await fetch(
      `https://api.trongrid.io/v1/transactions/${encodeURIComponent(
        cleanHash
      )}/events?only_confirmed=true&limit=200`,
      {
        headers: {
          "TRON-PRO-API-KEY": apiKey
        }
      }
    );

    if (response.ok) {
      const json =
        await response.json();

      events = Array.isArray(json?.data)
        ? json.data
        : [];
    }
  } catch {
    events = [];
  }

  let received = 0;

  for (const event of events) {
    if (
      String(
        event?.event_name || ""
      ).toLowerCase() !== "transfer"
    ) {
      continue;
    }

    const contract = String(
      event?.contract_address ||
      event?.address ||
      ""
    );

    const normalizedContract =
      contract.startsWith("41")
        ? (() => {
            try {
              return TronWeb.address.fromHex(
                contract
              );
            } catch {
              return contract;
            }
          })()
        : contract;

    if (
      normalizedContract !==
        USDT_CONTRACT &&
      contract !== USDT_CONTRACT &&
      !contract.endsWith(
        USDT_CONTRACT.slice(-40)
      )
    ) {
      continue;
    }

    let to =
      event?.result?.to ||
      event?.result?.["1"] ||
      event?.result?.["0"] ||
      null;

    let value =
      event?.result?.value ||
      event?.result?.["2"] ||
      null;

    if (
      !to &&
      event?.topics?.length >= 3
    ) {
      to =
        topicToAddress(
          event.topics[2]
        );
    }

    if (
      value == null &&
      event?.data
    ) {
      value =
        topicToAmount(
          event.data
        );
    }

    if (!to) continue;

    let normalizedTo = to;

    try {
      if (
        String(to).startsWith("41")
      ) {
        normalizedTo =
          TronWeb.address.fromHex(
            String(to)
          );
      }
    } catch {
      continue;
    }

    if (
      normalizedTo !==
      treasuryAddress
    ) {
      continue;
    }

    let amount =
      Number(value || 0);

    if (
      !Number.isFinite(amount) ||
      amount <= 0
    ) {
      amount =
        topicToAmount(
          event.data
        );
    }

    if (
      Number.isFinite(amount) &&
      amount > 0
    ) {
      received += amount;
    }
  }

  received =
    roundMoney(
      received,
      USDT_DECIMALS
    );

  if (received <= 0) {
    return {
      confirmed: false,
      pending: true,
      reason:
        "Transfer USDT para a carteira Treasury ainda não foi confirmado.",
      received: 0
    };
  }

  const expected =
    Number(requestedAmount);

  /*
   * requestedAmount = 0 significa:
   * aceitar o valor REAL encontrado na blockchain.
   *
   * Se foi informado um valor, o depósito
   * precisa receber pelo menos esse valor.
   */
  if (
    Number.isFinite(expected) &&
    expected > 0 &&
    received + 0.000001 < expected
  ) {
    return {
      confirmed: false,
      pending: false,
      reason:
        `Valor recebido insuficiente. Recebido: ${received} USDT.`,
      received
    };
  }

  return {
    confirmed: true,
    pending: false,
    received,
    tx_hash: cleanHash
  };
}

/* =========================================================
   WALLETS
========================================================= */

async function getOrCreateWallet(asset) {
  const normalizedAsset =
    String(asset).toUpperCase();

  const existing = await sql`
    SELECT
      id,
      wallet_address,
      network,
      asset,
      balance,
      status,
      user_id
    FROM wallets
    WHERE asset = ${normalizedAsset}
    ORDER BY id ASC
    LIMIT 1
  `;

  if (existing.length) {
    return existing[0];
  }

  const address =
    normalizedAsset === "USDT"
      ? getTreasuryAddress()
      : null;

  const inserted = await sql`
    INSERT INTO wallets (
      wallet_address,
      network,
      asset,
      balance,
      status,
      created_at,
      updated_at
    )
    VALUES (
      ${address},
      ${normalizedAsset === "USDT"
        ? "TRON"
        : "MZN"},
      ${normalizedAsset},
      0,
      'ACTIVE',
      NOW(),
      NOW()
    )
    RETURNING *
  `;

  return inserted[0];
}

/* =========================================================
   DEPÓSITO MZN
========================================================= */

async function registerMZNDeposit(body) {
  const amount =
    Number(body.amount);

  const source =
    normalizeSource(
      body.source
    );

  const description =
    String(
      body.description || ""
    ).trim();

  if (
    !Number.isFinite(amount) ||
    amount < MIN_MZN
  ) {
    return {
      status: 400,
      body: {
        success: false,
        message:
          `Valor mínimo: ${MIN_MZN} MZN.`
      }
    };
  }

  if (
    amount > MAX_MZN
  ) {
    return {
      status: 400,
      body: {
        success: false,
        message:
          `Valor máximo: ${MAX_MZN} MZN.`
      }
    };
  }

  if (!isValidSource(source)) {
    return {
      status: 400,
      body: {
        success: false,
        message:
          "Fonte de depósito inválida."
      }
    };
  }

  const reference =
    String(
      body.reference || ""
    ).trim() ||
    makeReference("MZN");

  const existing =
    await sql`
      SELECT
        id,
        reference,
        status,
        amount
      FROM transactions
      WHERE reference = ${reference}
      LIMIT 1
    `;

  if (existing.length) {
    return {
      status: 200,
      body: {
        success: true,
        status:
          existing[0].status,
        reference:
          existing[0].reference,
        amount:
          existing[0].amount,
        message:
          existing[0].status ===
          "COMPLETED"
            ? "Depósito já confirmado."
            : "Depósito continua pendente."
      }
    };
  }

  await getOrCreateWallet("MZN");

  await sql`
    INSERT INTO transactions (
      user_id,
      type,
      asset,
      amount,
      status,
      reference,
      created_at
    )
    VALUES (
      'ADMIN',
      'DEPOSIT_MZN',
      'MZN',
      ${amount},
      'PENDING',
      ${reference},
      NOW()
    )
  `;

  return {
    status: 200,
    body: {
      success: true,
      status: "PENDING",
      reference,
      amount,
      source,
      description,
      message:
        "Depósito registado como PENDING. O saldo só será atualizado após confirmação real."
    }
  };
}

/* =========================================================
   CONFIRMAR MZN
========================================================= */

async function confirmMZNDeposit(body) {
  const reference =
    String(
      body.reference || ""
    ).trim();

  if (!reference) {
    return {
      status: 400,
      body: {
        success: false,
        message:
          "reference é obrigatório."
      }
    };
  }

  await getOrCreateWallet("MZN");

  const result =
    await sql`
      WITH pending AS (
        SELECT
          id,
          amount
        FROM transactions
        WHERE reference = ${reference}
          AND type = 'DEPOSIT_MZN'
          AND asset = 'MZN'
          AND status = 'PENDING'
        FOR UPDATE
      ),
      wallet_update AS (
        UPDATE wallets
        SET
          balance =
            balance + pending.amount,
          updated_at = NOW()
        FROM pending
        WHERE wallets.asset = 'MZN'
        RETURNING
          pending.id,
          pending.amount
      )
      UPDATE transactions
      SET status = 'COMPLETED'
      WHERE id IN (
        SELECT id
        FROM wallet_update
      )
      RETURNING
        id,
        amount,
        reference,
        status
    `;

  if (!result.length) {
    const existing =
      await sql`
        SELECT
          id,
          amount,
          reference,
          status
        FROM transactions
        WHERE reference = ${reference}
          AND type = 'DEPOSIT_MZN'
        LIMIT 1
      `;

    if (
      existing.length &&
      existing[0].status ===
        "COMPLETED"
    ) {
      return {
        status: 200,
        body: {
          success: true,
          status: "COMPLETED",
          already_confirmed: true,
          transaction:
            existing[0]
        }
      };
    }

    return {
      status: 404,
      body: {
        success: false,
        message:
          "Depósito pendente não encontrado."
      }
    };
  }

  return {
    status: 200,
    body: {
      success: true,
      status: "COMPLETED",
      transaction: result[0],
      message:
        "Depósito MZN confirmado e saldo atualizado."
    }
  };
}

/* =========================================================
   DEPÓSITO USDT
========================================================= */

async function registerUSDTDeposit(body) {
  const requestedAmount =
    positiveNumber(
      body.amount
    ) || 0;

  const txHash =
    String(
      body.tx_hash ||
      body.blockchain_tx_hash ||
      ""
    ).trim();

  const source =
    normalizeSource(
      body.source ||
        "USDT_TRON"
    );

  if (!/^[a-fA-F0-9]{64}$/.test(txHash)) {
    return {
      status: 400,
      body: {
        success: false,
        message:
          "TX hash TRON inválido."
      }
    };
  }

  if (
    source !== "USDT_TRON"
  ) {
    return {
      status: 400,
      body: {
        success: false,
        message:
          "Depósito USDT deve usar USDT_TRON."
      }
    };
  }

  await getOrCreateWallet("USDT");

  const existing =
    await sql`
      SELECT
        id,
        reference,
        amount,
        status,
        blockchain_tx_hash
      FROM transactions
      WHERE blockchain_tx_hash = ${txHash}
      LIMIT 1
    `;

  if (existing.length) {
    if (
      existing[0].status ===
      "COMPLETED"
    ) {
      return {
        status: 200,
        body: {
          success: true,
          status: "COMPLETED",
          already_confirmed: true,
          transaction:
            existing[0]
        }
      };
    }

    if (
      existing[0].status ===
      "PENDING"
    ) {
      const verification =
        await verifyUsdtTransfer(
          txHash,
          existing[0].amount
        );

      if (
        verification.confirmed
      ) {
        return await confirmUSDTDeposit({
          reference:
            existing[0].reference,
          tx_hash: txHash
        });
      }

      return {
        status: 200,
        body: {
          success: true,
          status: "PENDING",
          reference:
            existing[0].reference,
          message:
            verification.reason
        }
      };
    }

    return {
      status: 409,
      body: {
        success: false,
        message:
          "TX hash já existe no histórico."
      }
    };
  }

  const reference =
    String(
      body.reference || ""
    ).trim() ||
    makeReference("USDT");

  /*
   * O amount enviado pelo browser NÃO é
   * usado como saldo definitivo.
   *
   * O valor final vem da blockchain.
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
      'ADMIN',
      'DEPOSIT_USDT',
      'USDT',
      ${requestedAmount},
      'PENDING',
      ${reference},
      ${txHash},
      NOW()
    )
  `;

  const verification =
    await verifyUsdtTransfer(
      txHash,
      requestedAmount
    );

  if (
    !verification.confirmed
  ) {
    if (
      !verification.pending
    ) {
      await sql`
        UPDATE transactions
        SET status = 'FAILED'
        WHERE reference = ${reference}
          AND status = 'PENDING'
      `;
    }

    return {
      status: 200,
      body: {
        success: true,
        status:
          verification.pending
            ? "PENDING"
            : "FAILED",
        reference,
        tx_hash: txHash,
        message:
          verification.reason
      }
    };
  }

  /*
   * Guarda inicialmente o valor real
   * encontrado na blockchain.
   */
  await sql`
    UPDATE transactions
    SET amount = ${verification.received}
    WHERE reference = ${reference}
      AND status = 'PENDING'
  `;

  return await confirmUSDTDeposit({
    reference,
    tx_hash: txHash
  });
}

/* =========================================================
   CONFIRMAR USDT
========================================================= */

async function confirmUSDTDeposit(body) {
  const reference =
    String(
      body.reference || ""
    ).trim();

  const txHash =
    String(
      body.tx_hash || ""
    ).trim();

  if (!reference) {
    return {
      status: 400,
      body: {
        success: false,
        message:
          "reference é obrigatório."
      }
    };
  }

  await getOrCreateWallet("USDT");

  const pending =
    await sql`
      SELECT
        id,
        amount,
        reference,
        status,
        blockchain_tx_hash
      FROM transactions
      WHERE reference = ${reference}
        AND type = 'DEPOSIT_USDT'
        AND asset = 'USDT'
      LIMIT 1
    `;

  if (!pending.length) {
    return {
      status: 404,
      body: {
        success: false,
        message:
          "Depósito USDT não encontrado."
      }
    };
  }

  const transaction =
    pending[0];

  if (
    transaction.status ===
    "COMPLETED"
  ) {
    return {
      status: 200,
      body: {
        success: true,
        status: "COMPLETED",
        already_confirmed: true,
        transaction
      }
    };
  }

  const hash =
    txHash ||
    String(
      transaction.blockchain_tx_hash ||
        ""
    ).trim();

  if (!/^[a-fA-F0-9]{64}$/.test(hash)) {
    return {
      status: 400,
      body: {
        success: false,
        message:
          "TX hash não encontrado ou inválido."
      }
    };
  }

  /*
   * Novamente verificamos a blockchain.
   * Nunca confiamos apenas no valor da BD.
   */
  const verification =
    await verifyUsdtTransfer(
      hash,
      0
    );

  if (
    !verification.confirmed
  ) {
    return {
      status: 200,
      body: {
        success: true,
        status:
          verification.pending
            ? "PENDING"
            : "FAILED",
        reference,
        tx_hash: hash,
        message:
          verification.reason
      }
    };
  }

  const realAmount =
    Number(
      verification.received
    );

  /*
   * Atualização atómica:
   *
   * - somente PENDING pode ser creditado;
   * - valor vem da blockchain;
   * - uma segunda chamada não credita novamente.
   */
  const result =
    await sql`
      WITH pending AS (
        SELECT
          id
        FROM transactions
        WHERE reference = ${reference}
          AND type = 'DEPOSIT_USDT'
          AND asset = 'USDT'
          AND status = 'PENDING'
        FOR UPDATE
      ),
      wallet_update AS (
        UPDATE wallets
        SET
          balance =
            balance + ${realAmount},
          updated_at = NOW()
        WHERE asset = 'USDT'
          AND EXISTS (
            SELECT 1
            FROM pending
          )
        RETURNING id
      )
      UPDATE transactions
      SET
        status = 'COMPLETED',
        amount = ${realAmount},
        blockchain_tx_hash = ${hash}
      WHERE id IN (
        SELECT id
        FROM pending
      )
      AND EXISTS (
        SELECT 1
        FROM wallet_update
      )
      RETURNING
        id,
        amount,
        reference,
        status,
        blockchain_tx_hash
    `;

  if (!result.length) {
    const existing =
      await sql`
        SELECT
          id,
          amount,
          reference,
          status,
          blockchain_tx_hash
        FROM transactions
        WHERE reference = ${reference}
        LIMIT 1
      `;

    if (
      existing.length &&
      existing[0].status ===
        "COMPLETED"
    ) {
      return {
        status: 200,
        body: {
          success: true,
          status: "COMPLETED",
          already_confirmed: true,
          transaction:
            existing[0]
        }
      };
    }

    return {
      status: 409,
      body: {
        success: false,
        message:
          "Não foi possível confirmar o depósito de forma segura."
      }
    };
  }

  return {
    status: 200,
    body: {
      success: true,
      status: "COMPLETED",
      transaction: result[0],
      message:
        "Depósito USDT confirmado na TRON. O valor creditado foi obtido da blockchain."
    }
  };
}

/* =========================================================
   CONVERSÃO MZN -> USDT
========================================================= */

async function convertMZNToUSDT(body) {
  const amountMZN =
    Number(
      body.amount_mzn
    );

  if (
    !Number.isFinite(
      amountMZN
    ) ||
    amountMZN < MIN_MZN ||
    amountMZN > MAX_MZN
  ) {
    return {
      status: 400,
      body: {
        success: false,
        message:
          `Valor deve estar entre ${MIN_MZN} e ${MAX_MZN} MZN.`
      }
    };
  }

  /*
   * Taxa REAL atual.
   *
   * Não usa RATE=64.
   */
  let rate;

  try {
    rate =
      await getRealUsdtMznRate(
        true
      );
  } catch (error) {
    return {
      status: 503,
      body: {
        success: false,
        code:
          "RATE_UNAVAILABLE",
        message:
          "A taxa cambial real não está disponível neste momento. A conversão foi bloqueada para proteger o saldo.",
        detail:
          error.message
      }
    };
  }

  const usdtAmount =
    roundMoney(
      amountMZN /
        rate.value,
      USDT_DECIMALS
    );

  if (
    !Number.isFinite(
      usdtAmount
    ) ||
    usdtAmount <= 0
  ) {
    return {
      status: 400,
      body: {
        success: false,
        message:
          "Quantidade USDT calculada inválida."
      }
    };
  }

  const reference =
    String(
      body.reference || ""
    ).trim() ||
    makeReference(
      "LIQUIDITY"
    );

  /*
   * IMPORTANTE:
   *
   * A operação inteira é atómica.
   *
   * Não existe mais o problema:
   *
   * 1. debitar MZN
   * 2. descobrir que não há USDT
   *
   * Agora os dois saldos são verificados
   * antes de qualquer alteração.
   */
  const result =
    await sql`
      WITH wallets_locked AS (
        SELECT
          id,
          asset,
          balance
        FROM wallets
        WHERE asset IN ('MZN', 'USDT')
        FOR UPDATE
      ),
      balances AS (
        SELECT
          MAX(
            CASE
              WHEN asset = 'MZN'
              THEN balance
            END
          ) AS mzn_balance,
          MAX(
            CASE
              WHEN asset = 'USDT'
              THEN balance
            END
          ) AS usdt_balance
        FROM wallets_locked
      ),
      operation AS (
        SELECT
          mzn_balance,
          usdt_balance
        FROM balances
        WHERE mzn_balance >= ${amountMZN}
          AND usdt_balance >= ${usdtAmount}
      ),
      mzn_debit AS (
        UPDATE wallets
        SET
          balance =
            balance - ${amountMZN},
          updated_at = NOW()
        WHERE asset = 'MZN'
          AND EXISTS (
            SELECT 1
            FROM operation
          )
        RETURNING id
      ),
      usdt_reserve AS (
        UPDATE wallets
        SET
          balance =
            balance - ${usdtAmount},
          updated_at = NOW()
        WHERE asset = 'USDT'
          AND EXISTS (
            SELECT 1
            FROM operation
          )
          AND EXISTS (
            SELECT 1
            FROM mzn_debit
          )
        RETURNING id
      )
      SELECT
        (SELECT COUNT(*) FROM mzn_debit)
          AS mzn_debited,
        (SELECT COUNT(*) FROM usdt_reserve)
          AS usdt_reserved
    `;

  const row =
    result[0] || {};

  const mznDebited =
    Number(
      row.mzn_debited || 0
    );

  const usdtReserved =
    Number(
      row.usdt_reserved || 0
    );

  if (
    mznDebited !== 1 ||
    usdtReserved !== 1
  ) {
    return {
      status: 400,
      body: {
        success: false,
        message:
          "Saldo MZN ou reserva real de USDT insuficiente. Nenhum saldo foi alterado."
      }
    };
  }

  /*
   * Registo contabilístico.
   */
  await sql`
    INSERT INTO transactions (
      user_id,
      type,
      asset,
      amount,
      status,
      reference,
      created_at
    )
    VALUES (
      'ADMIN',
      'CONVERSION',
      'MZN',
      ${amountMZN},
      'COMPLETED',
      ${reference},
      NOW()
    )
  `;

  await sql`
    INSERT INTO transactions (
      user_id,
      type,
      asset,
      amount,
      status,
      reference,
      created_at
    )
    VALUES (
      'ADMIN',
      'RESERVE_IN',
      'USDT',
      ${usdtAmount},
      'RESERVED',
      ${reference},
      NOW()
    )
  `;

  return {
    status: 200,
    body: {
      success: true,
      status: "COMPLETED",
      reference,

      rate: rate.value,

      market_rate:
        rate.marketRate,

      usd_mzn:
        rate.usdMzn,

      usdt_usd:
        rate.usdtUsd,

      spread_percent:
        rate.spreadPercent,

      rate_source:
        rate.source,

      rate_updated_at:
        rate.updatedAt,

      mzn:
        amountMZN,

      usdt:
        usdtAmount,

      message:
        "Conversão concluída usando taxa cambial atual e reserva real de USDT."
    }
  };
}

/* =========================================================
   LIBERTAR RESERVA
========================================================= */

async function releaseReservation(body) {
  const reference =
    String(
      body.reference || ""
    ).trim();

  if (!reference) {
    return {
      status: 400,
      body: {
        success: false,
        message:
          "reference é obrigatório."
      }
    };
  }

  const rows =
    await sql`
      SELECT
        id,
        amount,
        status
      FROM transactions
      WHERE reference = ${reference}
        AND type = 'RESERVE_IN'
        AND asset = 'USDT'
        AND status = 'RESERVED'
      LIMIT 1
    `;

  if (!rows.length) {
    return {
      status: 404,
      body: {
        success: false,
        message:
          "Reserva USDT não encontrada."
      }
    };
  }

  const amount =
    Number(rows[0].amount);

  /*
   * A libertação também é atómica.
   */
  const result =
    await sql`
      WITH reservation AS (
        SELECT
          id,
          amount
        FROM transactions
        WHERE id = ${rows[0].id}
          AND status = 'RESERVED'
        FOR UPDATE
      ),
      wallet_update AS (
        UPDATE wallets
        SET
          balance =
            balance + reservation.amount,
          updated_at = NOW()
        FROM reservation
        WHERE wallets.asset = 'USDT'
        RETURNING
          reservation.id
      )
      UPDATE transactions
      SET status = 'COMPLETED'
      WHERE id IN (
        SELECT id
        FROM wallet_update
      )
      RETURNING id
    `;

  if (!result.length) {
    return {
      status: 409,
      body: {
        success: false,
        message:
          "A reserva já foi processada."
      }
    };
  }

  return {
    status: 200,
    body: {
      success: true,
      status: "COMPLETED",
      reference,
      released_usdt:
        amount
    }
  };
}

/* =========================================================
   PENDING DEPOSITS
========================================================= */

async function getPendingDeposits() {
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
      WHERE status = 'PENDING'
        AND type IN (
          'DEPOSIT_MZN',
          'DEPOSIT_USDT'
        )
      ORDER BY created_at DESC
    `;

  return rows;
}

/* =========================================================
   FONTES DE LIQUIDEZ
========================================================= */

async function getLiquiditySources() {
  const pagarConfigured =
    Boolean(
      process.env.PAGAR_API_KEY &&
      process.env.PAGAR_WEBHOOK_SECRET
    );

  let rateStatus;

  try {
    const rate =
      await getRealUsdtMznRate();

    rateStatus = {
      available: true,
      rate: rate.value,
      market_rate:
        rate.marketRate,
      source: rate.source,
      updated_at:
        rate.updatedAt
    };
  } catch {
    rateStatus = {
      available: false,
      rate: null,
      source: null
    };
  }

  return [
    {
      code: "MPESA_BUSINESS",
      name: "M-Pesa",
      asset: "MZN",
      provider: "Pagar",
      configured:
        pagarConfigured,
      active: false
    },
    {
      code: "EMOLA_BUSINESS",
      name: "e-Mola",
      asset: "MZN",
      provider: "Pagar",
      configured:
        pagarConfigured,
      active: false
    },
    {
      code: "BANK",
      name: "Banco",
      asset: "MZN",
      configured: true,
      active: false
    },
    {
      code: "USDT_TRON",
      name: "USDT TRC20",
      asset: "USDT",
      network: "TRON",
      configured:
        Boolean(
          getTreasuryAddress()
        ),
      active: true
    },
    {
      code: "EXTERNAL_WALLET",
      name: "Carteira externa",
      asset: "USDT",
      network: "TRON",
      configured: true,
      active: false
    },
    {
      code: "USDT_PURCHASE",
      name: "Compra de USDT",
      asset: "USDT",
      network: "TRON",
      configured: true,
      active: true
    },
    {
      code: "LIQUIDITY_PARTNER",
      name: "Parceiro de liquidez",
      asset: "USDT",
      configured: false,
      active: false
    },
    {
      code: "MANUAL_APPROVED",
      name: "Manual aprovado",
      asset: "MZN/USDT",
      configured: true,
      active: false
    },
    {
      code: "REAL_FX_RATE",
      name: "Motor cambial",
      asset: "MZN/USDT",
      configured:
        rateStatus.available,
      active:
        rateStatus.available,
      rate:
        rateStatus.rate,
      market_rate:
        rateStatus.market_rate,
      source:
        rateStatus.source,
      updated_at:
        rateStatus.updated_at
    }
  ];
}

/* =========================================================
   DASHBOARD
========================================================= */

async function getDashboard() {
  const mznWallet =
    await getOrCreateWallet(
      "MZN"
    );

  const usdtWallet =
    await getOrCreateWallet(
      "USDT"
    );

  const pendingDeposits =
    await getPendingDeposits();

  let rate = null;

  try {
    rate =
      await getRealUsdtMznRate();
  } catch {
    rate = null;
  }

  const orders =
    await sql`
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
        updated_at,
        pagar_payment_id,
        blockchain_tx_hash
      FROM orders
      ORDER BY created_at DESC
      LIMIT 50
    `;

  const withdrawals =
    await sql`
      SELECT
        id,
        withdrawal_id,
        user_id,
        amount,
        asset,
        network,
        destination_address,
        status,
        tx_hash,
        created_at,
        updated_at,
        order_id
      FROM withdrawals
      ORDER BY created_at DESC
      LIMIT 50
    `;

  const transactions =
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
      ORDER BY created_at DESC
      LIMIT 100
    `;

  const binanceTransfers =
    await sql`
      SELECT
        order_id,
        amount,
        usdt_amount,
        status,
        blockchain_tx_hash,
        created_at,
        updated_at
      FROM orders
      WHERE operation =
        'BUY_USDT_ADMIN'
      ORDER BY created_at DESC
      LIMIT 50
    `;

  return {
    treasury: {
      mzn:
        Number(
          mznWallet?.balance || 0
        ),

      usdt:
        Number(
          usdtWallet?.balance || 0
        ),

      /*
       * Compatibilidade com o
       * frontend antigo.
       */
      rate:
        rate?.value || null,

      market_rate:
        rate?.marketRate || null,

      usd_mzn:
        rate?.usdMzn || null,

      usdt_usd:
        rate?.usdtUsd || null,

      rate_source:
        rate?.source || null,

      rate_updated_at:
        rate?.updatedAt || null,

      min_mzn:
        MIN_MZN,

      max_mzn:
        MAX_MZN,

      wallet_address:
        getTreasuryAddress(),

      network:
        "TRON",

      asset:
        "USDT",

      contract:
        USDT_CONTRACT,

      decimals:
        USDT_DECIMALS
    },

    liquidity: {
      real_usdt_available:
        Number(
          usdtWallet?.balance || 0
        ),

      mzn_available:
        Number(
          mznWallet?.balance || 0
        )
    },

    pending_deposits:
      pendingDeposits,

    orders,

    binance_transfers:
      binanceTransfers,

    withdrawals,

    transactions,

    sources:
      await getLiquiditySources(),

    system: {
      rate:
        rate?.value || null,

      market_rate:
        rate?.marketRate || null,

      usd_mzn:
        rate?.usdMzn || null,

      usdt_usd:
        rate?.usdtUsd || null,

      rate_source:
        rate?.source || null,

      rate_updated_at:
        rate?.updatedAt || null,

      min_mzn:
        MIN_MZN,

      max_mzn:
        MAX_MZN,

      network:
        "TRON",

      usdt_contract:
        USDT_CONTRACT,

      pagar_configured:
        Boolean(
          process.env.PAGAR_API_KEY &&
          process.env.PAGAR_WEBHOOK_SECRET
        ),

      pagar_payout_configured:
        Boolean(
          process.env.PAGAR_API_KEY &&
          process.env.PAGAR_SIGNING_SECRET
        ),

      tron_configured:
        Boolean(
          process.env.TRON_PRO_API_KEY &&
          getTreasuryAddress()
        ),

      fx_configured:
        Boolean(
          rate
        )
    }
  };
}

/* =========================================================
   REGISTER FUNDING
========================================================= */

async function registerFunding(body) {
  const type =
    String(
      body.type || ""
    )
      .trim()
      .toUpperCase();

  if (type === "MZN") {
    return await registerMZNDeposit({
      ...body,
      source:
        normalizeSource(
          body.source ||
            "MANUAL_APPROVED"
        )
    });
  }

  if (type === "USDT") {
    return await registerUSDTDeposit({
      ...body,
      source:
        "USDT_TRON"
    });
  }

  return {
    status: 400,
    body: {
      success: false,
      message:
        "type deve ser MZN ou USDT."
    }
  };
}

/* =========================================================
   ACTION
========================================================= */

async function handleAction(
  req,
  res,
  action
) {
  switch (action) {
    case "sources":
    case "liquidity_sources":
      return res.status(200).json({
        success: true,
        sources:
          await getLiquiditySources()
      });

    case "rate":
    case "exchange_rate":
    case "fx_rate":
      try {
        const rate =
          await getRealUsdtMznRate(
            true
          );

        return res.status(200).json({
          success: true,
          data: rate
        });
      } catch (error) {
        return res.status(503).json({
          success: false,
          code:
            "RATE_UNAVAILABLE",
          message:
            "Taxa cambial real indisponível.",
          detail:
            error.message
        });
      }

    case "dashboard":
      return res.status(200).json({
        success: true,
        data:
          await getDashboard()
      });

    case "register_mzn_deposit":
      return sendResult(
        res,
        await registerMZNDeposit(
          req.body || {}
        )
      );

    case "confirm_mzn_deposit":
      return sendResult(
        res,
        await confirmMZNDeposit(
          req.body || {}
        )
      );

    case "register_usdt_deposit":
      return sendResult(
        res,
        await registerUSDTDeposit(
          req.body || {}
        )
      );

    case "confirm_usdt_deposit":
      return sendResult(
        res,
        await confirmUSDTDeposit(
          req.body || {}
        )
      );

    case "convert_mzn_to_usdt":
      return sendResult(
        res,
        await convertMZNToUSDT(
          req.body || {}
        )
      );

    case "release_reservation":
      return sendResult(
        res,
        await releaseReservation(
          req.body || {}
        )
      );

    case "register_funding":
      return sendResult(
        res,
        await registerFunding(
          req.body || {}
        )
      );

    case "pending_deposits":
      return res.status(200).json({
        success: true,
        pending_deposits:
          await getPendingDeposits()
      });

    default:
      return res.status(400).json({
        success: false,
        message:
          "Ação inválida."
      });
  }
}

/* =========================================================
   RESPONSE
========================================================= */

function sendResult(
  res,
  result
) {
  return res
    .status(result.status)
    .json(result.body);
}

/* =========================================================
   HANDLER
========================================================= */

export default async function handler(
  req,
  res
) {
  try {
    const session =
      requireAdmin(
        req,
        res
      );

    if (!session) return;

    const url =
      new URL(
        req.url,
        `https://${
          req.headers.host ||
          "localhost"
        }`
      );

    const action =
      String(
        url.searchParams.get(
          "action"
        ) || "dashboard"
      )
        .trim()
        .toLowerCase();

    if (
      req.method === "GET"
    ) {
      if (
        action === "sources" ||
        action ===
          "liquidity_sources" ||
        action ===
          "dashboard" ||
        action ===
          "pending_deposits" ||
        action === "rate" ||
        action ===
          "exchange_rate" ||
        action ===
          "fx_rate"
      ) {
        return await handleAction(
          req,
          res,
          action
        );
      }

      return res.status(405).json({
        success: false,
        message:
          "Método não permitido."
      });
    }

    if (
      req.method !== "POST"
    ) {
      return res.status(405).json({
        success: false,
        message:
          "Método não permitido."
      });
    }

    return await handleAction(
      req,
      res,
      action
    );
  } catch (error) {
    console.error(
      "admin-withdrawals error:",
      error
    );

    return res.status(500).json({
      success: false,
      message:
        "Erro interno do servidor."
    });
  }
}
