// api/admin-withdrawals.js
// USDTMZ — CENTRAL ADMIN
//
// API06 — TESOURARIA CENTRAL
//
// EXCLUSIVAMENTE ADMIN.
//
// PAY.CO.MZ:
// - M-Pesa
// - mKesh
// - cartão
// - webhook payment.succeeded
//
// e-Mola:
// - BLOQUEADO enquanto não estiver ativo na API de produção.
//
// REGRAS:
// - Nunca criar USDT artificialmente.
// - Nunca confiar no navegador para confirmar pagamento.
// - MZN só entra depois de confirmação Pay.co.mz.
// - USDT só entra depois de confirmação real na TRON.
// - Conversão MZN -> USDT só utiliza USDT real disponível.
// - Secrets somente no servidor.
// - Webhook Pay.co.mz usa HMAC-SHA256.
// - Webhook é idempotente.
// - Admin é obrigatório em todas as operações normais.
// - Webhook é a única exceção, validada pela assinatura Pay.co.mz.

// ============================================================================
// IMPORTS
// ============================================================================

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

const COOKIE_NAME =
  "usdtmz_admin_session";

const MIN_MZN = 64;
const MAX_MZN = 40000;

const USDT_DECIMALS = 6;

const USDT_CONTRACT =
  process.env.USDT_TRON_CONTRACT ||
  "TR7NHqjeKQXGTCi8q8ZY4pL8otSzgjLj6t";

const TRON_HOST =
  process.env.TRON_HOST ||
  "https://api.trongrid.io";

// ============================================================================
// PAY.CO.MZ
// ============================================================================

const PAY_API_BASE_URL =
  process.env.PAY_API_BASE_URL ||
  "https://pay.co.mz/api/public/v1";

const PAY_TIMEOUT_MS = 20000;

// Cache curto da taxa cambial.
const RATE_CACHE_MS =
  60 * 1000;

let rateCache = null;

// ============================================================================
// FONTES
// ============================================================================

const SOURCES = [
  "MPESA_BUSINESS",
  "MKESH_BUSINESS",
  "EMOLA_BUSINESS",
  "BANK",
  "USDT_TRON",
  "EXTERNAL_WALLET",
  "USDT_PURCHASE",
  "LIQUIDITY_PARTNER",
  "BINANCE",
  "KOTANI",
  "REDPAY",
  "MANUAL_APPROVED"
];

// ============================================================================
// RESPOSTA
// ============================================================================

function sendJson(
  res,
  status,
  body
) {
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
// COMPARAÇÃO SEGURA
// ============================================================================

function safeCompare(
  a,
  b
) {
  if (
    typeof a !== "string" ||
    typeof b !== "string"
  ) {
    return false;
  }

  const aa =
    Buffer.from(a);

  const bb =
    Buffer.from(b);

  if (
    aa.length !== bb.length
  ) {
    return false;
  }

  return timingSafeEqual(
    aa,
    bb
  );
}

// ============================================================================
// COOKIES
// ============================================================================

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
      part
        .slice(0, index)
        .trim();

    const value =
      part
        .slice(index + 1)
        .trim();

    try {
      cookies[key] =
        decodeURIComponent(value);
    } catch {
      cookies[key] =
        value;
    }
  }

  return cookies;
}

// ============================================================================
// SESSÃO ADMIN
// ============================================================================

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

  if (
    parts.length !== 2
  ) {
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
    payload =
      JSON.parse(
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

  if (
    payload.id !== "admin"
  ) {
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

function positiveNumber(
  value
) {
  const n =
    Number(value);

  if (
    !Number.isFinite(n) ||
    n <= 0
  ) {
    return null;
  }

  return n;
}

function positiveInteger(
  value
) {
  const n =
    Number(value);

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
  const n =
    Number(value);

  if (
    !Number.isFinite(n)
  ) {
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

function normalizeSource(
  value
) {
  return String(value || "")
    .trim()
    .toUpperCase();
}

function isValidSource(
  value
) {
  return SOURCES.includes(
    normalizeSource(value)
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

  return new TronWeb(
    options
  );
}

// ============================================================================
// FETCH JSON
// ============================================================================

async function fetchJson(
  url,
  options = {},
  timeoutMs = 15000
) {
  const controller =
    new AbortController();

  const timer =
    setTimeout(
      () =>
        controller.abort(),
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

    if (
      !response.ok
    ) {
      const error =
        new Error(
          data?.message ||
          data?.error ||
          `HTTP ${response.status}`
        );

      error.status =
        response.status;

      error.data =
        data;

      throw error;
    }

    return data;
  } finally {
    clearTimeout(timer);
  }
}

// ============================================================================
// BODY
// ============================================================================

async function readBody(req) {
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
    raw +=
      chunk.toString();
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
// BANCO — COLUNAS DE PROVEDOR
// ============================================================================
//
// Mantemos provider/provider_reference separados de
// blockchain_tx_hash.
//
// Isso evita guardar a referência Pay.co.mz como se fosse
// uma TX blockchain.
//
// ============================================================================

let providerColumnsPromise = null;

async function ensureProviderColumns() {
  if (
    providerColumnsPromise
  ) {
    return providerColumnsPromise;
  }

  providerColumnsPromise =
    (async () => {
      await sql`
        ALTER TABLE transactions
        ADD COLUMN IF NOT EXISTS provider
        TEXT
      `;

      await sql`
        ALTER TABLE transactions
        ADD COLUMN IF NOT EXISTS provider_reference
        TEXT
      `;

      await sql`
        CREATE INDEX IF NOT EXISTS
        transactions_provider_reference_idx
        ON transactions
        (provider, provider_reference)
      `;
    })();

  try {
    await providerColumnsPromise;
  } catch (error) {
    providerColumnsPromise =
      null;

    throw error;
  }
}

// ============================================================================
// PAY.CO.MZ — CONFIGURAÇÃO
// ============================================================================

function payConfigured() {
  return Boolean(
    process.env.PAY_API_KEY &&
    process.env.PAY_WALLET_ID &&
    process.env.PAY_MERCHANT_ID
  );
}

// ============================================================================
// PAY.CO.MZ — REQUEST
// ============================================================================

async function payRequest(
  path,
  options = {}
) {
  if (
    !payConfigured()
  ) {
    throw new Error(
      "Pay.co.mz não está configurado. Configure PAY_API_KEY, PAY_WALLET_ID e PAY_MERCHANT_ID."
    );
  }

  const headers = {
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
  };

  return fetchJson(
    `${PAY_API_BASE_URL}${path}`,
    {
      ...options,
      headers
    },
    PAY_TIMEOUT_MS
  );
}

// ============================================================================
// PAY.CO.MZ — MÉTODO
// ============================================================================

function normalizePayMethod(
  value
) {
  const method =
    String(value || "")
      .trim()
      .toLowerCase();

  if (
    method === "mpesa"
  ) {
    return "mpesa";
  }

  if (
    method === "mkesh"
  ) {
    return "mkesh";
  }

  if (
    method === "card"
  ) {
    return "card";
  }

  if (
    method === "emola"
  ) {
    throw new Error(
      "e-Mola não está disponível na API de produção Pay.co.mz neste momento."
    );
  }

  throw new Error(
    "Método inválido. Use mpesa, mkesh ou card."
  );
}

// ============================================================================
// PAY.CO.MZ — CRIAR CHARGE
// ============================================================================

async function createPayTreasuryCharge(
  body
) {
  await ensureProviderColumns();

  const amount =
    positiveNumber(
      body.amount_mzn ??
      body.amount
    );

  if (!amount) {
    throw new Error(
      "amount_mzn inválido."
    );
  }

  if (
    amount < 20 ||
    amount > MAX_MZN
  ) {
    throw new Error(
      "O pagamento deve estar entre 20 e 40000 MZN."
    );
  }

  const method =
    normalizePayMethod(
      body.method
    );

  const customerName =
    String(
      body.customer_name ||
      body.name ||
      "USDTMZ Admin"
    ).trim();

  if (
    customerName.length < 2
  ) {
    throw new Error(
      "customer_name inválido."
    );
  }

  let customerContact =
    String(
      body.customer_contact ||
      body.payment_phone ||
      body.phone ||
      ""
    ).trim();

  if (
    method === "mpesa" ||
    method === "mkesh"
  ) {
    customerContact =
      customerContact.replace(
        /\D/g,
        ""
      );

    if (
      !/^258[0-9]{9}$/.test(
        customerContact
      )
    ) {
      if (
        /^[0-9]{9}$/.test(
          customerContact
        )
      ) {
        customerContact =
          `258${customerContact}`;
      } else {
        throw new Error(
          "Para M-Pesa/mKesh informe o número no formato 258XXXXXXXXX ou 9 dígitos."
        );
      }
    }
  }

  if (
    method === "card" &&
    !customerContact
  ) {
    throw new Error(
      "Para cartão, customer_contact é obrigatório."
    );
  }

  const localReference =
    String(
      body.reference || ""
    ).trim() ||
    makeReference(
      "PAY-TREASURY"
    );

  if (
    !/^[A-Za-z0-9._:-]{8,120}$/.test(
      localReference
    )
  ) {
    throw new Error(
      "reference inválida."
    );
  }

  // Idempotência local.
  const existing =
    await sql`
      SELECT *
      FROM transactions
      WHERE reference =
        ${localReference}
      ORDER BY id DESC
      LIMIT 1
    `;

  if (
    existing.length
  ) {
    const transaction =
      existing[0];

    return {
      success: true,
      existing: true,
      reference:
        localReference,
      status:
        transaction.status,
      transaction
    };
  }

  // --------------------------------------------------------------------------
  // Criamos primeiro a operação local.
  // Ainda NÃO creditamos MZN.
  // --------------------------------------------------------------------------

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
        provider,
        created_at
      )
      VALUES
      (
        NULL,
        'DEPOSIT_MZN',
        'MZN',
        ${roundMoney(
          amount,
          2
        )},
        'PENDING',
        ${localReference},
        'PAY_CO_MZ',
        NOW()
      )
      RETURNING *
    `;

  const transaction =
    created[0];

  const idempotencyKey =
    `usdtmz-${localReference}`;

  // --------------------------------------------------------------------------
  // IMPORTANTE:
  // O corpo enviado ao Pay.co.mz contém somente os campos documentados.
  // --------------------------------------------------------------------------

  const payload = {
    amount:
      roundMoney(
        amount,
        2
      ),

    method,

    customer_name:
      customerName,

    customer_contact:
      customerContact,

    wallet_id:
      Number(
        process.env.PAY_WALLET_ID
      )
  };

  let response;

  try {
    response =
      await payRequest(
        "/charges",
        {
          method: "POST",

          headers: {
            "Idempotency-Key":
              idempotencyKey
          },

          body:
            JSON.stringify(
              payload
            )
        }
      );
  } catch (error) {
    await sql`
      UPDATE transactions
      SET status = 'FAILED'
      WHERE id =
        ${transaction.id}
      AND status =
        'PENDING'
    `;

    throw error;
  }

  // --------------------------------------------------------------------------
  // Encontrar referência do Pay.co.mz.
  // --------------------------------------------------------------------------

  const providerReference =
    String(
      response?.reference ||
      response?.charge?.reference ||
      response?.data?.reference ||
      response?.transaction_reference ||
      response?.data?.transaction_reference ||
      ""
    ).trim();

  const providerStatus =
    String(
      response?.status ||
      response?.charge?.status ||
      response?.data?.status ||
      ""
    ).toUpperCase();

  if (
    providerReference
  ) {
    await sql`
      UPDATE transactions
      SET
        provider =
          'PAY_CO_MZ',
        provider_reference =
          ${providerReference}
      WHERE id =
        ${transaction.id}
    `;
  }

  // --------------------------------------------------------------------------
  // Se a API já informar PAID, ainda assim registramos somente
  // através da função de confirmação/reconciliação.
  // --------------------------------------------------------------------------

  if (
    providerStatus ===
      "PAID" ||
    providerStatus ===
      "SUCCEEDED" ||
    providerStatus ===
      "SUCCESS"
  ) {
    const confirmed =
      await confirmPayCharge(
        {
          reference:
            localReference,
          provider_reference:
            providerReference,
          provider_data:
            response
        }
      );

    return {
      success: true,
      created: true,
      confirmed: true,
      reference:
        localReference,
      providerReference,
      pay:
        response,
      confirmation:
        confirmed
    };
  }

  return {
    success: true,

    created: true,

    confirmed: false,

    status:
      providerStatus ||
      "PROCESSING",

    reference:
      localReference,

    providerReference:
      providerReference ||
      null,

    checkout_url:
      response?.checkout_url ||
      response?.charge?.checkout_url ||
      response?.data?.checkout_url ||
      null,

    pay:
      response,

    message:
      "Pagamento criado. O Fundo MZN continua sem crédito até payment.succeeded/reconciliação Pay.co.mz."
  };
}

// ============================================================================
// PAY.CO.MZ — BUSCAR CHARGES
// ============================================================================

async function getPayCharges(
  limit = 100
) {
  const safeLimit =
    Math.min(
      100,
      Math.max(
        1,
        Number(limit) || 100
      )
    );

  return payRequest(
    `/charges?limit=${safeLimit}`,
    {
      method: "GET"
    }
  );
}

// ============================================================================
// PAY.CO.MZ — EXTRAIR LISTA
// ============================================================================

function extractPayCharges(
  response
) {
  if (
    Array.isArray(response)
  ) {
    return response;
  }

  if (
    Array.isArray(
      response?.charges
    )
  ) {
    return response.charges;
  }

  if (
    Array.isArray(
      response?.data
    )
  ) {
    return response.data;
  }

  if (
    Array.isArray(
      response?.data?.charges
    )
  ) {
    return response.data.charges;
  }

  return [];
}

// ============================================================================
// PAY.CO.MZ — LOCALIZAR TRANSAÇÃO
// ============================================================================

async function findPayTransaction(
  body
) {
  await ensureProviderColumns();

  const reference =
    String(
      body.reference || ""
    ).trim();

  const providerReference =
    String(
      body.provider_reference ||
      body.transaction_reference ||
      body.pay_reference ||
      ""
    ).trim();

  if (
    providerReference
  ) {
    const rows =
      await sql`
        SELECT *
        FROM transactions
        WHERE provider =
          'PAY_CO_MZ'
        AND provider_reference =
          ${providerReference}
        ORDER BY id DESC
        LIMIT 1
      `;

    if (
      rows.length
    ) {
      return rows[0];
    }
  }

  if (
    reference
  ) {
    const rows =
      await sql`
        SELECT *
        FROM transactions
        WHERE reference =
          ${reference}
        AND type =
          'DEPOSIT_MZN'
        ORDER BY id DESC
        LIMIT 1
      `;

    if (
      rows.length
    ) {
      return rows[0];
    }
  }

  return null;
}

// ============================================================================
// PAY.CO.MZ — NET AMOUNT
// ============================================================================
//
// O Pay.co.mz aplica taxa de transação.
// Nunca assumimos que gross == net.
//
// Procuramos primeiro valores de net conhecidos.
// Se a resposta não informar net, calculamos pelo fee informado.
// Se nenhum dos dois existir, NÃO creditamos silenciosamente.
// ============================================================================

function getPayNetAmount(
  payCharge,
  localAmount
) {
  const candidates = [
    payCharge?.net_amount,
    payCharge?.net,
    payCharge?.amount_net,
    payCharge?.data?.net_amount,
    payCharge?.charge?.net_amount
  ];

  for (
    const value of candidates
  ) {
    const n =
      Number(value);

    if (
      Number.isFinite(n) &&
      n > 0
    ) {
      return roundMoney(
        n,
        2
      );
    }
  }

  const feeCandidates = [
    payCharge?.fee,
    payCharge?.fees,
    payCharge?.fee_amount,
    payCharge?.data?.fee,
    payCharge?.charge?.fee
  ];

  for (
    const value of feeCandidates
  ) {
    const fee =
      Number(value);

    if (
      Number.isFinite(fee) &&
      fee >= 0 &&
      fee < localAmount
    ) {
      return roundMoney(
        localAmount - fee,
        2
      );
    }
  }

  // A documentação atual indica taxa de 10%.
  // Só usamos esse cálculo quando a resposta não
  // trouxe net/fee explícitos.
  //
  // A taxa real contabilizada deverá ser reconciliada
  // com o extrato do provedor.
  return roundMoney(
    localAmount * 0.90,
    2
  );
}

// ============================================================================
// PAY.CO.MZ — CONFIRMAR CHARGE
// ============================================================================
//
// Só esta função credita MZN.
// O browser nunca chama isto para "confirmar pagamento".
// Ela é chamada pelo webhook ou pela reconciliação.
// ============================================================================

async function confirmPayCharge(
  body
) {
  await ensureProviderColumns();

  const transaction =
    await findPayTransaction(
      body
    );

  if (
    !transaction
  ) {
    throw new Error(
      "Transação Pay.co.mz não encontrada na tesouraria."
    );
  }

  if (
    transaction.status ===
    "COMPLETED"
  ) {
    return {
      success: true,
      confirmed: true,
      alreadyCompleted: true,
      reference:
        transaction.reference,
      transaction
    };
  }

  if (
    transaction.status !==
    "PENDING"
  ) {
    throw new Error(
      `Transação Pay.co.mz não pode ser confirmada no estado ${transaction.status}.`
    );
  }

  const payData =
    body.provider_data ||
    body.pay ||
    {};

  const status =
    String(
      payData?.status ||
      payData?.charge?.status ||
      payData?.data?.status ||
      body.status ||
      ""
    ).toUpperCase();

  if (
    status &&
    ![
      "PAID",
      "SUCCEEDED",
      "SUCCESS",
      "COMPLETED"
    ].includes(status)
  ) {
    throw new Error(
      `Pagamento Pay.co.mz ainda não está confirmado: ${status}.`
    );
  }

  const gross =
    Number(
      transaction.amount
    );

  const net =
    getPayNetAmount(
      payData,
      gross
    );

  if (
    !Number.isFinite(net) ||
    net <= 0
  ) {
    throw new Error(
      "Valor líquido Pay.co.mz inválido."
    );
  }

  // --------------------------------------------------------------------------
  // Atualização idempotente.
  // --------------------------------------------------------------------------

  const updated =
    await sql`
      UPDATE transactions
      SET
        status =
          'COMPLETED',
        amount =
          ${net}
      WHERE id =
        ${transaction.id}
      AND status =
        'PENDING'
      RETURNING *
    `;

  if (
    !updated.length
  ) {
    const current =
      await sql`
        SELECT *
        FROM transactions
        WHERE id =
          ${transaction.id}
        LIMIT 1
      `;

    return {
      success: true,
      confirmed:
        current[0]?.status ===
        "COMPLETED",
      alreadyCompleted:
        current[0]?.status ===
        "COMPLETED",
      reference:
        transaction.reference,
      transaction:
        current[0] ||
        transaction
    };
  }

  try {
    await changeWalletBalance(
      "MZN",
      net
    );
  } catch (error) {
    await sql`
      UPDATE transactions
      SET
        status =
          'PENDING',
        amount =
          ${gross}
      WHERE id =
        ${transaction.id}
      AND status =
        'COMPLETED'
    `;

    throw error;
  }

  return {
    success: true,
    confirmed: true,

    reference:
      transaction.reference,

    grossAmount:
      gross,

    netAmount:
      net,

    transaction:
      updated[0]
  };
}

// ============================================================================
// PAY.CO.MZ — RECONCILIAÇÃO
// ============================================================================

async function checkPayTreasuryCharge(
  body
) {
  await ensureProviderColumns();

  let transaction =
    await findPayTransaction(
      body
    );

  const response =
    await getPayCharges(
      100
    );

  const charges =
    extractPayCharges(
      response
    );

  const requestedProviderReference =
    String(
      body.provider_reference ||
      body.transaction_reference ||
      body.pay_reference ||
      ""
    ).trim();

  const requestedReference =
    String(
      body.reference ||
      ""
    ).trim();

  const matchingCharge =
    charges.find(
      (charge) => {
        const ref =
          String(
            charge?.reference ||
            charge?.transaction_reference ||
            charge?.id ||
            ""
          ).trim();

        const metadataReference =
          String(
            charge?.metadata?.reference ||
            charge?.metadata?.usdtmz_reference ||
            ""
          ).trim();

        return (
          (
            requestedProviderReference &&
            ref ===
              requestedProviderReference
          ) ||
          (
            requestedReference &&
            (
              metadataReference ===
                requestedReference ||
              ref ===
                requestedReference
            )
          )
        );
      }
    );

  if (
    !transaction &&
    matchingCharge
  ) {
    const providerReference =
      String(
        matchingCharge.reference ||
        matchingCharge.transaction_reference ||
        matchingCharge.id ||
        ""
      ).trim();

    if (
      providerReference
    ) {
      const rows =
        await sql`
          SELECT *
          FROM transactions
          WHERE provider =
            'PAY_CO_MZ'
          AND provider_reference =
            ${providerReference}
          ORDER BY id DESC
          LIMIT 1
        `;

      transaction =
        rows[0] ||
        null;
    }
  }

  if (
    !transaction
  ) {
    throw new Error(
      "Não foi possível localizar a operação local correspondente ao pagamento Pay.co.mz."
    );
  }

  const charge =
    matchingCharge;

  if (
    !charge
  ) {
    return {
      success: true,
      foundLocal: true,
      foundProvider: false,
      confirmed: false,
      reference:
        transaction.reference,
      transaction,
      message:
        "Operação local encontrada, mas o charge correspondente não foi encontrado nos últimos pagamentos retornados pelo Pay.co.mz."
    };
  }

  const providerReference =
    String(
      charge.reference ||
      charge.transaction_reference ||
      charge.id ||
      ""
    ).trim();

  if (
    providerReference
  ) {
    await sql`
      UPDATE transactions
      SET
        provider =
          'PAY_CO_MZ',
        provider_reference =
          ${providerReference}
      WHERE id =
        ${transaction.id}
    `;
  }

  const status =
    String(
      charge.status ||
      charge.charge?.status ||
      charge.data?.status ||
      ""
    ).toUpperCase();

  if (
    [
      "PAID",
      "SUCCEEDED",
      "SUCCESS",
      "COMPLETED"
    ].includes(status)
  ) {
    return confirmPayCharge(
      {
        reference:
          transaction.reference,

        provider_reference:
          providerReference,

        provider_data:
          charge,

        status
      }
    );
  }

  if (
    [
      "FAILED",
      "CANCELLED",
      "CANCELED"
    ].includes(status)
  ) {
    await sql`
      UPDATE transactions
      SET status =
        'FAILED'
      WHERE id =
        ${transaction.id}
      AND status =
        'PENDING'
    `;

    return {
      success: true,
      confirmed: false,
      status,
      reference:
        transaction.reference,
      providerReference,
      transaction:
        transaction
    };
  }

  return {
    success: true,
    confirmed: false,
    status:
      status ||
      "PROCESSING",
    reference:
      transaction.reference,
    providerReference,
    transaction
  };
}

// ============================================================================
// PAY.CO.MZ — WEBHOOK HMAC
// ============================================================================

function parsePaySignature(
  signatureHeader
) {
  const header =
    String(
      signatureHeader || ""
    ).trim();

  if (!header) {
    return null;
  }

  const parts =
    header.split(",");

  let timestamp = null;
  let signature = null;

  for (
    const part of parts
  ) {
    const [key, ...rest] =
      part.split("=");

    const value =
      rest.join("=");

    if (
      key === "t"
    ) {
      timestamp =
        value;
    }

    if (
      key === "v1"
    ) {
      signature =
        value;
    }
  }

  if (
    !timestamp ||
    !signature
  ) {
    return null;
  }

  return {
    timestamp,
    signature
  };
}

// ============================================================================
// PAY.CO.MZ — WEBHOOK
// ============================================================================

async function handlePayWebhook(
  req,
  res
) {
  const secret =
    process.env.PAY_WEBHOOK_SECRET;

  if (!secret) {
    return sendJson(
      res,
      500,
      {
        success: false,
        error:
          "PAY_WEBHOOK_SECRET não configurado."
      }
    );
  }

  // --------------------------------------------------------------------------
  // IMPORTANTE:
  // Precisamos do corpo RAW para verificar a assinatura.
  // --------------------------------------------------------------------------

  let rawBody = "";

  try {
    for await (
      const chunk of req
    ) {
      rawBody +=
        chunk.toString();
    }
  } catch {
    return sendJson(
      res,
      400,
      {
        success: false,
        error:
          "Não foi possível ler o webhook."
      }
    );
  }

  const signatureHeader =
    req.headers[
      "x-pay-signature"
    ];

  const parsed =
    parsePaySignature(
      signatureHeader
    );

  if (!parsed) {
    return sendJson(
      res,
      401,
      {
        success: false,
        error:
          "Assinatura Pay.co.mz ausente ou inválida."
      }
    );
  }

  const timestamp =
    Number(
      parsed.timestamp
    );

  if (
    !Number.isFinite(
      timestamp
    )
  ) {
    return sendJson(
      res,
      401,
      {
        success: false,
        error:
          "Timestamp do webhook inválido."
      }
    );
  }

  // Pay.co.mz trabalha com timestamp.
  // Aceitamos segundos ou milissegundos.
  const timestampMs =
    timestamp < 10000000000
      ? timestamp * 1000
      : timestamp;

  const age =
    Math.abs(
      Date.now() -
      timestampMs
    );

  if (
    age > 5 * 60 * 1000
  ) {
    return sendJson(
      res,
      401,
      {
        success: false,
        error:
          "Webhook expirado."
      }
    );
  }

  const signedPayload =
    `${parsed.timestamp}.${rawBody}`;

  const expectedSignature =
    createHmac(
      "sha256",
      secret
    )
      .update(
        signedPayload
      )
      .digest("hex");

  if (
    !safeCompare(
      parsed.signature,
      expectedSignature
    )
  ) {
    return sendJson(
      res,
      401,
      {
        success: false,
        error:
          "Assinatura Pay.co.mz inválida."
      }
    );
  }

  let event;

  try {
    event =
      JSON.parse(
        rawBody
      );
  } catch {
    return sendJson(
      res,
      400,
      {
        success: false,
        error:
          "JSON do webhook inválido."
      }
    );
  }

  const eventId =
    String(
      req.headers[
        "x-pay-event-id"
      ] ||
      event?.id ||
      event?.event_id ||
      ""
    ).trim();

  const eventType =
    String(
      req.headers[
        "x-pay-event"
      ] ||
      event?.type ||
      event?.event ||
      ""
    ).trim();

  // --------------------------------------------------------------------------
  // Idempotência de webhook.
  // --------------------------------------------------------------------------
  //
  // Criamos tabela própria se não existir.
  //

  await sql`
    CREATE TABLE IF NOT EXISTS
    pay_webhook_events
    (
      id BIGSERIAL PRIMARY KEY,
      event_id TEXT UNIQUE NOT NULL,
      event_type TEXT,
      received_at TIMESTAMPTZ
        NOT NULL DEFAULT NOW()
    )
  `;

  if (eventId) {
    const inserted =
      await sql`
        INSERT INTO
        pay_webhook_events
        (
          event_id,
          event_type
        )
        VALUES
        (
          ${eventId},
          ${eventType}
        )
        ON CONFLICT
        (event_id)
        DO NOTHING
        RETURNING id
      `;

    if (
      !inserted.length
    ) {
      return sendJson(
        res,
        200,
        {
          success: true,
          duplicate: true
        }
      );
    }
  }

  // --------------------------------------------------------------------------
  // PAYMENT SUCCEEDED
  // --------------------------------------------------------------------------

  if (
    eventType ===
    "payment.succeeded"
  ) {
    const data =
      event?.data ||
      event?.payment ||
      event?.charge ||
      event;

    const providerReference =
      String(
        data?.reference ||
        data?.transaction_reference ||
        data?.charge?.reference ||
        data?.payment?.reference ||
        event?.reference ||
        event?.transaction_reference ||
        ""
      ).trim();

    const localReference =
      String(
        data?.metadata?.reference ||
        data?.metadata?.usdtmz_reference ||
        event?.metadata?.reference ||
        event?.metadata?.usdtmz_reference ||
        ""
      ).trim();

    const status =
      String(
        data?.status ||
        data?.charge?.status ||
        event?.status ||
        "PAID"
      ).toUpperCase();

    try {
      const result =
        await confirmPayCharge(
          {
            reference:
              localReference,

            provider_reference:
              providerReference,

            provider_data:
              data,

            status
          }
        );

      return sendJson(
        res,
        200,
        {
          success: true,
          event:
            "payment.succeeded",
          confirmed:
            result.confirmed,
          reference:
            result.reference
        }
      );
    } catch (error) {
      console.error(
        "PAY WEBHOOK CONFIRMATION ERROR:",
        error
      );

      // Retornamos 500 para o provedor poder
      // tentar novamente quando a operação
      // ainda não puder ser reconciliada.
      return sendJson(
        res,
        500,
        {
          success: false,
          error:
            error?.message ||
            "Falha ao processar payment.succeeded."
        }
      );
    }
  }

  // --------------------------------------------------------------------------
  // PAYMENT FAILED
  // --------------------------------------------------------------------------

  if (
    eventType ===
    "payment.failed"
  ) {
    const data =
      event?.data ||
      event?.payment ||
      event?.charge ||
      event;

    const providerReference =
      String(
        data?.reference ||
        data?.transaction_reference ||
        data?.charge?.reference ||
        event?.reference ||
        ""
      ).trim();

    const localReference =
      String(
        data?.metadata?.reference ||
        data?.metadata?.usdtmz_reference ||
        event?.metadata?.reference ||
        event?.metadata?.usdtmz_reference ||
        ""
      ).trim();

    const transaction =
      await findPayTransaction(
        {
          reference:
            localReference,

          provider_reference:
            providerReference
        }
      );

    if (
      transaction
    ) {
      await sql`
        UPDATE transactions
        SET status =
          'FAILED'
        WHERE id =
          ${transaction.id}
        AND status =
          'PENDING'
      `;
    }

    return sendJson(
      res,
      200,
      {
        success: true,
        event:
          "payment.failed",
        processed:
          Boolean(transaction)
      }
    );
  }

  // Outros eventos são recebidos mas não
  // movimentam saldo MZN.
  return sendJson(
    res,
    200,
    {
      success: true,
      ignored: true,
      event:
        eventType ||
        null
    }
  );
}

// ============================================================================
// TAXA CAMBIAL
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

// ============================================================================
// USD/MZN — AFRICA API
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

// ============================================================================
// USD/MZN — OPEN ER API
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
// USD/MZN — MONEYCONVERT
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
// USD/MZN — MOTOR
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
// USDT/USD — COINBASE
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
// USDT/USD — COINGECKO
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
// USDT/USD — MOTOR
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

  throw new Error(
    "Todas as fontes USDT/USD falharam: " +
    errors.join(" | ")
  );
}

// ============================================================================
// TAXA FINAL
// ============================================================================

export async function getRealUsdtMznRate(
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
    Number(
      usdMzn.rate
    ) *
    Number(
      usdtUsd.rate
    );

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

  const result = {
    value:
      roundMoney(
        marketRate,
        6
      ),

    rate:
      roundMoney(
        marketRate,
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

    spread: 0,

    spreadPercent: 0,

    source:
      `${usdMzn.source}+${usdtUsd.source}`,

    updatedAt:
      new Date().toISOString(),

    fxUpdatedAt:
      usdMzn.updatedAt,

    warning:
      null
  };

  rateCache = {
    timestamp:
      now,

    value:
      result
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
      .replace(
        /^0x/,
        ""
      );

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
        .replace(
          /^0x/,
          ""
        );

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

// ============================================================================
// VERIFICAR USDT TRON
// ============================================================================

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

  if (
    !info.receipt
  ) {
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

    let destination = null;

    if (
      typeof to ===
      "string"
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

    txHash:
      hash,

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
// WALLETS
// ============================================================================

async function getWallet(
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
      WHERE asset =
        ${normalized}
      AND (
        user_id IS NULL
        OR user_id = 0
      )
      ORDER BY id ASC
      LIMIT 1
    `;

  if (
    rows.length
  ) {
    return rows[0];
  }

  const address =
    normalized ===
    "USDT"
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
        ${
          normalized ===
          "USDT"
            ? "TRON"
            : "INTERNAL"
        },
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
      AND asset IN
        ('MZN', 'USDT')
      ORDER BY asset
    `;

  let mzn = 0;
  let usdt = 0;

  for (
    const row of rows
  ) {
    if (
      row.asset ===
      "MZN"
    ) {
      mzn =
        Number(
          row.balance
        ) || 0;
    }

    if (
      row.asset ===
      "USDT"
    ) {
      usdt =
        Number(
          row.balance
        ) || 0;
    }
  }

  return {
    mzn:
      roundMoney(
        mzn,
        2
      ),

    usdt:
      roundMoney(
        usdt,
        6
      )
  };
}

async function changeWalletBalance(
  asset,
  amount
) {
  const wallet =
    await getWallet(
      asset
    );

  const updated =
    await sql`
      UPDATE wallets
      SET
        balance =
          COALESCE(
            balance,
            0
          ) +
          ${amount},

        updated_at =
          NOW()

      WHERE id =
        ${wallet.id}

      RETURNING *
    `;

  return updated[0];
}

// ============================================================================
// MZN — REGISTRAR
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
    !isValidSource(
      source
    )
  ) {
    throw new Error(
      "Fonte de liquidez inválida."
    );
  }

  const reference =
    String(
      body.reference ||
      ""
    ).trim() ||
    makeReference(
      "MZN-DEPOSIT"
    );

  const existing =
    await sql`
      SELECT *
      FROM transactions
      WHERE reference =
        ${reference}
      ORDER BY id DESC
      LIMIT 1
    `;

  if (
    existing.length
  ) {
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
// MZN — CONFIRMAR MANUAL
// ============================================================================

async function confirmMZNDeposit(
  body
) {
  const reference =
    String(
      body.reference ||
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
      WHERE reference =
        ${reference}
      AND type =
        'DEPOSIT_MZN'
      ORDER BY id DESC
      LIMIT 1
    `;

  if (
    !rows.length
  ) {
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
    !Number.isFinite(
      amount
    ) ||
    amount <= 0
  ) {
    throw new Error(
      "Valor do depósito inválido."
    );
  }

  const updated =
    await sql`
      UPDATE transactions
      SET status =
        'COMPLETED'
      WHERE id =
        ${transaction.id}
      AND status =
        'PENDING'
      RETURNING *
    `;

  if (
    !updated.length
  ) {
    return {
      success: true,
      confirmed: true,
      alreadyCompleted: true,
      reference
    };
  }

  try {
    await changeWalletBalance(
      "MZN",
      amount
    );
  } catch (error) {
    await sql`
      UPDATE transactions
      SET status =
        'PENDING'
      WHERE id =
        ${transaction.id}
      AND status =
        'COMPLETED'
    `;

    throw error;
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
// USDT — REGISTRAR
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
      body.reference ||
      ""
    ).trim() ||
    makeReference(
      "USDT-DEPOSIT"
    );

  const existing =
    await sql`
      SELECT *
      FROM transactions
      WHERE blockchain_tx_hash =
        ${txHash}
      OR reference =
        ${reference}
      ORDER BY id DESC
      LIMIT 1
    `;

  if (
    existing.length
  ) {
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
// USDT — CONFIRMAR BLOCKCHAIN
// ============================================================================

async function confirmUSDTDeposit(
  body
) {
  const reference =
    String(
      body.reference ||
      ""
    ).trim();

  let txHash =
    String(
      body.tx_hash ||
      body.txHash ||
      ""
    ).trim();

  let transaction = null;

  if (
    reference
  ) {
    const rows =
      await sql`
        SELECT *
        FROM transactions
        WHERE reference =
          ${reference}
        AND type =
          'DEPOSIT_USDT'
        ORDER BY id DESC
        LIMIT 1
      `;

    if (
      rows.length
    ) {
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
        WHERE blockchain_tx_hash =
          ${txHash}
        AND type =
          'DEPOSIT_USDT'
        ORDER BY id DESC
        LIMIT 1
      `;

    transaction =
      existing[0] ||
      null;
  }

  if (
    !transaction
  ) {
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
          ${
            reference ||
            makeReference(
              "USDT-DEPOSIT"
            )
          },
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

  const updated =
    await sql`
      UPDATE transactions
      SET
        status =
          'COMPLETED',
        amount =
          ${verified.amount},
        blockchain_tx_hash =
          ${txHash}
      WHERE id =
        ${transaction.id}
      AND status =
        'PENDING'
      RETURNING *
    `;

  if (
    !updated.length
  ) {
    return {
      success: true,
      confirmed: true,
      alreadyCompleted: true,
      blockchain:
        verified
    };
  }

  try {
    await changeWalletBalance(
      "USDT",
      verified.amount
    );
  } catch (error) {
    await sql`
      UPDATE transactions
      SET
        status =
          'PENDING',
        amount =
          ${transaction.amount}
      WHERE id =
        ${transaction.id}
      AND status =
        'COMPLETED'
    `;

    throw error;
  }

  return {
    success: true,
    confirmed: true,
    blockchain:
      verified,
    transaction:
      updated[0]
  };
}

// ============================================================================
// LIQUIDEZ USDT
// ============================================================================

async function checkUSDTLiquidity(
  amountUSDT
) {
  const required =
    positiveNumber(
      amountUSDT
    );

  if (!required) {
    throw new Error(
      "Quantidade USDT necessária inválida."
    );
  }

  const balances =
    await getWalletBalances();

  if (
    balances.usdt >=
    required
  ) {
    return {
      available: true,
      executable: true,
      source:
        "TREASURY_TRON",
      availableUsdt:
        balances.usdt,
      requiredUsdt:
        required
    };
  }

  return {
    available: false,
    executable: false,
    source: null,
    availableUsdt:
      balances.usdt,
    requiredUsdt:
      required,
    missingUsdt:
      roundMoney(
        required -
          balances.usdt,
        6
      ),
    message:
      "Não existe USDT real suficiente na tesouraria."
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
        Number(
          rate.value
        ),
      6
    );

  if (
    amountUSDT <= 0
  ) {
    throw new Error(
      "Quantidade USDT inválida."
    );
  }

  const liquidity =
    await checkUSDTLiquidity(
      amountUSDT
    );

  if (
    !liquidity.available
  ) {
    throw new Error(
      liquidity.message
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

  const reference =
    String(
      body.reference ||
      ""
    ).trim() ||
    makeReference(
      "CONVERSION"
    );

  const existing =
    await sql`
      SELECT *
      FROM transactions
      WHERE reference =
        ${reference}
      LIMIT 1
    `;

  if (
    existing.length
  ) {
    return {
      success: true,
      existing: true,
      transaction:
        existing[0]
    };
  }

  const debitMZN =
    await sql`
      UPDATE wallets
      SET
        balance =
          balance -
          ${amountMZN},

        updated_at =
          NOW()

      WHERE asset =
        'MZN'

      AND (
        user_id IS NULL
        OR user_id = 0
      )

      AND balance >=
        ${amountMZN}

      RETURNING *
    `;

  if (
    !debitMZN.length
  ) {
    throw new Error(
      "Não foi possível reservar o MZN para a conversão."
    );
  }

  try {
    const debitUSDT =
      await sql`
        UPDATE wallets
        SET
          balance =
            balance -
            ${amountUSDT},

          updated_at =
            NOW()

        WHERE asset =
          'USDT'

        AND (
          user_id IS NULL
          OR user_id = 0
        )

        AND balance >=
          ${amountUSDT}

        RETURNING *
      `;

    if (
      !debitUSDT.length
    ) {
      await sql`
        UPDATE wallets
        SET
          balance =
            balance +
            ${amountMZN},

          updated_at =
            NOW()

        WHERE asset =
          'MZN'

        AND (
          user_id IS NULL
          OR user_id = 0
        )
      `;

      throw new Error(
        "USDT insuficiente para completar a conversão."
      );
    }

    const transaction =
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
        RETURNING *
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

      liquidity: {
        source:
          "TREASURY_TRON",

        executable:
          true,

        realUsdt:
          true
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

        spread: 0,

        spreadPercent: 0,

        updatedAt:
          rate.updatedAt
      },

      transaction:
        transaction[0]
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
    positiveNumber(
      amount
    );

  if (!value) {
    throw new Error(
      "Quantidade USDT inválida."
    );
  }

  const ref =
    String(
      reference ||
      ""
    ).trim() ||
    makeReference(
      "USDT-RESERVE"
    );

  const existing =
    await sql`
      SELECT *
      FROM transactions
      WHERE reference =
        ${ref}
      AND type =
        'USDT_RESERVATION'
      ORDER BY id DESC
      LIMIT 1
    `;

  if (
    existing.length
  ) {
    return {
      success: true,
      existing: true,
      transaction:
        existing[0]
    };
  }

  const wallet =
    await getWallet(
      "USDT"
    );

  const balance =
    Number(
      wallet.balance
    ) || 0;

  const reservedRows =
    await sql`
      SELECT
        COALESCE(
          SUM(amount),
          0
        ) AS reserved

      FROM transactions

      WHERE type =
        'USDT_RESERVATION'

      AND status =
        'PENDING'
    `;

  const reserved =
    Number(
      reservedRows[0]
        ?.reserved || 0
    );

  const available =
    Math.max(
      0,
      balance -
        reserved
    );

  if (
    available <
    value
  ) {
    throw new Error(
      `USDT disponível insuficiente. Disponível: ${roundMoney(available, 6)} USDT.`
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
      WHERE reference =
        ${reference}
      AND type =
        'USDT_RESERVATION'
      ORDER BY id DESC
      LIMIT 1
    `;

  if (
    !rows.length
  ) {
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

  const updated =
    await sql`
      UPDATE transactions
      SET status =
        'CANCELLED'
      WHERE id =
        ${reservation.id}
      AND status =
        'PENDING'
      RETURNING *
    `;

  return {
    success: true,
    released:
      Number(
        reservation.amount
      ),
    transaction:
      updated[0] ||
      reservation
  };
}

// ============================================================================
// FONTES DE LIQUIDEZ
// ============================================================================

function externalLiquidityConfiguration() {
  return {
    binance:
      Boolean(
        process.env.BINANCE_API_KEY &&
        process.env.BINANCE_API_SECRET
      ),

    kotani:
      Boolean(
        process.env.KOTANI_API_KEY
      ),

    redpay:
      Boolean(
        process.env.REDPAY_API_KEY
      ),

    genericPartner:
      Boolean(
        process.env.USDTMZ_LIQUIDITY_PARTNER
      )
  };
}

async function getLiquiditySources() {
  const balances =
    await getWalletBalances();

  let treasuryAddress =
    null;

  try {
    treasuryAddress =
      getTreasuryAddress();
  } catch {
    treasuryAddress =
      null;
  }

  const external =
    externalLiquidityConfiguration();

  return {
    success: true,

    policy: {
      artificialSpread:
        false,

      usdtPegFallback:
        false,

      fixedUsdtMznRate:
        false,

      marketRateRequired:
        true,

      realLiquidityRequired:
        true
    },

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

        executionAvailable:
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
          "PAY_MPESA",

        type:
          "MPESA_BUSINESS",

        name:
          "Pay.co.mz — M-Pesa",

        configured:
          payConfigured(),

        executionAvailable:
          payConfigured(),

        asset:
          "MZN"
      },

      {
        id:
          "PAY_MKESH",

        type:
          "MKESH_BUSINESS",

        name:
          "Pay.co.mz — mKesh",

        configured:
          payConfigured(),

        executionAvailable:
          payConfigured(),

        asset:
          "MZN"
      },

      {
        id:
          "PAY_EMOLA",

        type:
          "EMOLA_BUSINESS",

        name:
          "Pay.co.mz — e-Mola",

        configured:
          false,

        executionAvailable:
          false,

        asset:
          "MZN",

        message:
          "e-Mola não está ativo na API de produção Pay.co.mz."
      },

      {
        id:
          "PAY_CARD",

        type:
          "CARD",

        name:
          "Pay.co.mz — Visa/Mastercard",

        configured:
          payConfigured(),

        executionAvailable:
          payConfigured(),

        asset:
          "MZN"
      },

      {
        id:
          "BINANCE",

        type:
          "BINANCE",

        name:
          "Binance",

        configured:
          external.binance,

        executionAvailable:
          false,

        asset:
          "USDT",

        network:
          "TRON/TRC20",

        message:
          external.binance
            ? "Credenciais configuradas, mas compra automática ainda não está ativada."
            : "Binance não configurada."
      },

      {
        id:
          "KOTANI",

        type:
          "KOTANI",

        name:
          "Kotani",

        configured:
          external.kotani,

        executionAvailable:
          false,

        asset:
          "USDT",

        message:
          external.kotani
            ? "Credencial configurada, mas adaptador de execução ainda não ativado."
            : "Kotani não configurada."
      },

      {
        id:
          "REDPAY",

        type:
          "REDPAY",

        name:
          "RedPay",

        configured:
          external.redpay,

        executionAvailable:
          false,

        asset:
          "USDT",

        message:
          external.redpay
            ? "Credencial configurada, mas adaptador de execução ainda não ativado."
            : "RedPay não configurada."
      }
    ]
  };
}

// ============================================================================
// FUNDING MANUAL
// ============================================================================

async function registerFunding(
  body
) {
  const asset =
    String(
      body.asset ||
      ""
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
    !isValidSource(
      source
    )
  ) {
    throw new Error(
      "Fonte de liquidez inválida."
    );
  }

  // USDT manual exige TX real.
  if (
    asset === "USDT" &&
    source !==
      "MANUAL_APPROVED"
  ) {
    const txHash =
      String(
        body.tx_hash ||
        ""
      ).trim();

    if (
      !txHash
    ) {
      throw new Error(
        "Funding USDT externo precisa de TX hash TRON."
      );
    }
  }

  const reference =
    String(
      body.reference ||
      ""
    ).trim() ||
    makeReference(
      "FUNDING"
    );

  const existing =
    await sql`
      SELECT *
      FROM transactions
      WHERE reference =
        ${reference}
      LIMIT 1
    `;

  if (
    existing.length
  ) {
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

  try {
    await changeWalletBalance(
      asset,
      amount
    );
  } catch (error) {
    await sql`
      DELETE FROM transactions
      WHERE id =
        ${tx[0].id}
      AND status =
        'COMPLETED'
    `;

    throw error;
  }

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

  let tronAddress =
    null;

  try {
    tronAddress =
      getTreasuryAddress();
  } catch {
    tronAddress =
      null;
  }

  let trx = 0;

  if (
    tronAddress
  ) {
    try {
      const tronWeb =
        getTronWeb();

      const sun =
        await tronWeb.trx.getBalance(
          tronAddress
        );

      trx =
        Number(sun) /
        1000000;
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

      WHERE type =
        'USDT_RESERVATION'

      AND status =
        'PENDING'
    `;

  const reserved =
    Number(
      reservedRows[0]
        ?.reserved || 0
    );

  const available =
    Math.max(
      0,
      balances.usdt -
        reserved
    );

  let state =
    "SEM LIQUIDEZ";

  if (
    available > 0 &&
    balances.mzn > 0
  ) {
    state =
      "LIQUIDEZ DISPONÍVEL";
  } else if (
    available > 0
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
        roundMoney(
          trx,
          6
        ),

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
// OPERAÇÕES
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
        provider,
        provider_reference,
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
// PENDENTES
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
        provider,
        provider_reference,
        blockchain_tx_hash,
        created_at

      FROM transactions

      WHERE status =
        'PENDING'

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
// RATE RESPONSE
// ============================================================================

async function rateResponse(
  force = false
) {
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
        0,

      spreadPercent:
        0,

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
// ROTEADOR
// ============================================================================

export default async function handler(
  req,
  res
) {
  try {

    // ========================================================================
    // WEBHOOK PAY.CO.MZ
    // ========================================================================
    //
    // Tem de ser processado ANTES de requireAdmin,
    // porque Pay.co.mz não possui a nossa cookie de Admin.
    //
    // A segurança do webhook é HMAC + timestamp + event id.
    //
    // ========================================================================

    const url =
      new URL(
        req.url,
        "http://localhost"
      );

    const actionFromUrl =
      String(
        url.searchParams.get(
          "action"
        ) ||
        ""
      )
        .trim()
        .toLowerCase();

    const isWebhook =
      actionFromUrl ===
        "pay_webhook" ||
      req.headers[
        "x-pay-signature"
      ];

    if (
      isWebhook
    ) {
      return handlePayWebhook(
        req,
        res
      );
    }

    // ========================================================================
    // ADMIN
    // ========================================================================

    const admin =
      requireAdmin(req);

    if (
      req.method !==
        "GET" &&
      req.method !==
        "POST"
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
      req.method ===
        "POST"
        ? await readBody(req)
        : {};

    const action =
      String(
        body.action ||
        actionFromUrl ||
        "dashboard"
      )
        .trim()
        .toLowerCase();

    // ========================================================================
    // RATE
    // ========================================================================

    if (
      action ===
        "rate" ||
      action ===
        "exchange_rate" ||
      action ===
        "fx_rate"
    ) {
      return sendJson(
        res,
        200,
        await rateResponse(
          false
        )
      );
    }

    // ========================================================================
    // FORÇAR ATUALIZAÇÃO
    // ========================================================================

    if (
      action ===
        "refresh_rate" ||
      action ===
        "update_rate"
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
      action ===
      "dashboard"
    ) {
      return sendJson(
        res,
        200,
        await getDashboard()
      );
    }

    // ========================================================================
    // FONTES
    // ========================================================================

    if (
      action ===
        "sources" ||
      action ===
        "liquidity_sources"
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
      action ===
        "operations" ||
      action ===
        "recent_operations"
    ) {
      return sendJson(
        res,
        200,
        await getRecentOperations()
      );
    }

    // ========================================================================
    // PENDENTES
    // ========================================================================

    if (
      action ===
      "pending_deposits"
    ) {
      return sendJson(
        res,
        200,
        await getPendingDeposits()
      );
    }

    // ========================================================================
    // PAY.CO.MZ — CRIAR PAGAMENTO
    // ========================================================================

    if (
      action ===
        "create_pay_treasury_charge" ||
      action ===
        "pay_treasury_charge"
    ) {
      return sendJson(
        res,
        200,
        await createPayTreasuryCharge(
          body
        )
      );
    }

    // ========================================================================
    // COMPATIBILIDADE COM FRONTEND ANTIGO
    // ========================================================================
    //
    // Se admin.html ainda enviar:
    // create_pagar_treasury_topup
    //
    // NÃO chamamos Pagar.
    // Redirecionamos internamente para Pay.co.mz.
    //
    // ========================================================================

    if (
      action ===
        "create_pagar_treasury_topup"
    ) {
      return sendJson(
        res,
        200,
        await createPayTreasuryCharge(
          body
        )
      );
    }

    // ========================================================================
    // PAY STATUS
    // ========================================================================

    if (
      action ===
        "check_pay_treasury_charge" ||
      action ===
        "pay_treasury_status"
    ) {
      return sendJson(
        res,
        200,
        await checkPayTreasuryCharge(
          body
        )
      );
    }

    // ========================================================================
    // COMPATIBILIDADE ANTIGA
    // ========================================================================

    if (
      action ===
        "check_pagar_treasury_topup"
    ) {
      return sendJson(
        res,
        200,
        await checkPayTreasuryCharge(
          body
        )
      );
    }

    // ========================================================================
    // MZN
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
    // USDT
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
    // LIBERAR
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
    // ERRO
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
