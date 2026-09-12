import { neon } from "@neondatabase/serverless";
import {
  createHmac,
  createHash,
  timingSafeEqual,
  randomBytes
} from "node:crypto";
import { TronWeb } from "tronweb";

const sql = neon(process.env.DATABASE_URL);

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

const PAGAR_API_BASE_URL = String(
  process.env.PAGAR_API_BASE_URL ||
    "https://api.pagar.co.mz/api/v1"
).replace(/\/+$/, "");

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

    if (
      !payload.exp ||
      Date.now() >= Number(payload.exp)
    ) {
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
      message:
        "Sessão administrativa inválida ou expirada."
    });

    return null;
  }

  return session;
}

/* =========================================================
   UTILITÁRIOS
========================================================= */

function makeReference(prefix = "TREASURY") {
  return `${prefix}-${Date.now()}-${randomBytes(5).toString(
    "hex"
  )}`;
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
    return TronWeb.isAddress(
      String(address || "").trim()
    );
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
  const apiKey = String(
    process.env.TRON_PRO_API_KEY || ""
  ).trim();

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

  return (
    Math.round(Number(value) * factor) /
    factor
  );
}

function positiveNumber(value) {
  const number = Number(value);

  return Number.isFinite(number) && number > 0
    ? number
    : null;
}

function validMozambiquePhone(phone) {
  const value = String(phone || "")
    .trim()
    .replace(/\s+/g, "");

  return /^(?:258)?8[2-7][0-9]{7}$/.test(value);
}

function normalizePagarMethod(method) {
  const value = String(method || "")
    .trim()
    .toUpperCase();

  if (value === "MPESA" || value === "M-PESA") {
    return "MPESA";
  }

  if (value === "EMOLA" || value === "E-MOLA") {
    return "EMOLA";
  }

  return null;
}

/* =========================================================
   HTTP / JSON
========================================================= */

async function fetchJson(
  url,
  options = {},
  timeoutMs = 10000
) {
  const controller = new AbortController();

  const timeout = setTimeout(
    () => controller.abort(),
    timeoutMs
  );

  try {
    const response = await fetch(url, {
      ...options,
      signal: controller.signal,
      headers: {
        Accept: "application/json",
        ...(options.headers || {})
      }
    });

    const text = await response.text();

    let data = null;

    try {
      data = text ? JSON.parse(text) : null;
    } catch {
      throw new Error(
        `Resposta JSON inválida do fornecedor (HTTP ${response.status}).`
      );
    }

    if (!response.ok) {
      const message =
        data?.message ||
        data?.error ||
        data?.detail ||
        `Fornecedor respondeu HTTP ${response.status}.`;

      throw new Error(String(message));
    }

    return data;
  } catch (error) {
    if (error?.name === "AbortError") {
      throw new Error(
        "Tempo limite excedido ao consultar o fornecedor."
      );
    }

    throw error;
  } finally {
    clearTimeout(timeout);
  }
}

/* =========================================================
   PAGAR
========================================================= */

function getPagarConfig() {
  const apiKey = String(
    process.env.PAGAR_API_KEY || ""
  ).trim();

  const signingSecret = String(
    process.env.PAGAR_SIGNING_SECRET || ""
  ).trim();

  const webhookSecret = String(
    process.env.PAGAR_WEBHOOK_SECRET || ""
  ).trim();

  return {
    configured:
      Boolean(apiKey && signingSecret),

    webhookConfigured:
      Boolean(webhookSecret),

    apiKey,
    signingSecret,
    webhookSecret
  };
}

function buildPagarSignature({
  timestamp,
  nonce,
  method,
  url,
  body,
  signingSecret
}) {
  const rawBody = JSON.stringify(body ?? {});

  const bodyHash = createHash("sha256")
    .update(rawBody)
    .digest("hex");

  const canonicalPath = new URL(url).pathname;

  const canonical = [
    timestamp,
    nonce,
    method.toUpperCase(),
    canonicalPath,
    bodyHash
  ].join("\n");

  return createHmac(
    "sha256",
    signingSecret
  )
    .update(canonical)
    .digest("hex");
}

async function pagarPost(path, body, idempotencyKey) {
  const config = getPagarConfig();

  if (!config.apiKey) {
    throw new Error(
      "PAGAR_API_KEY não configurada no servidor."
    );
  }

  if (!config.signingSecret) {
    throw new Error(
      "PAGAR_SIGNING_SECRET não configurada no servidor."
    );
  }

  const url =
    `${PAGAR_API_BASE_URL}/` +
    String(path).replace(/^\/+/, "");

  const timestamp = String(
    Math.floor(Date.now() / 1000)
  );

  const nonce = randomBytes(16).toString("hex");

  const signature = buildPagarSignature({
    timestamp,
    nonce,
    method: "POST",
    url,
    body,
    signingSecret: config.signingSecret
  });

  return await fetchJson(
    url,
    {
      method: "POST",

      headers: {
        Authorization:
          `Bearer ${config.apiKey}`,

        "Content-Type":
          "application/json",

        "Idempotency-Key":
          String(idempotencyKey),

        "X-Pagar-Timestamp":
          timestamp,

        "X-Pagar-Nonce":
          nonce,

        "X-Pagar-Signature":
          `v1=${signature}`
      },

      body: JSON.stringify(body)
    },
    15000
  );
}

async function pagarGet(path) {
  const config = getPagarConfig();

  if (!config.apiKey) {
    throw new Error(
      "PAGAR_API_KEY não configurada no servidor."
    );
  }

  const url =
    `${PAGAR_API_BASE_URL}/` +
    String(path).replace(/^\/+/, "");

  return await fetchJson(
    url,
    {
      method: "GET",

      headers: {
        Authorization:
          `Bearer ${config.apiKey}`
      }
    },
    10000
  );
}

function extractPagarStatus(data) {
  const candidates = [
    data?.topup?.status,
    data?.data?.topup?.status,
    data?.status,
    data?.data?.status
  ];

  for (const candidate of candidates) {
    const value = String(
      candidate || ""
    )
      .trim()
      .toUpperCase();

    if (value) return value;
  }

  return null;
}

function extractPagarTopup(data) {
  return (
    data?.topup ||
    data?.data?.topup ||
    data?.data ||
    data ||
    {}
  );
}

/* =========================================================
   PAGAR — CRIAR TOP-UP DA TESOURARIA
========================================================= */

async function createPagarTreasuryTopup(body) {
  const amount = Number(body.amount);

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

  if (amount > MAX_MZN) {
    return {
      status: 400,
      body: {
        success: false,
        message:
          `Valor máximo: ${MAX_MZN} MZN.`
      }
    };
  }

  const method = normalizePagarMethod(
    body.method ||
      body.payment ||
      body.source
  );

  if (!method) {
    return {
      status: 400,
      body: {
        success: false,
        message:
          "Método deve ser MPESA ou EMOLA."
      }
    };
  }

  const paymentPhone = String(
    body.payment_phone ||
      body.paymentPhone ||
      body.phone ||
      ""
  )
    .trim()
    .replace(/\s+/g, "");

  if (!validMozambiquePhone(paymentPhone)) {
    return {
      status: 400,
      body: {
        success: false,
        message:
          "Número de telefone de Moçambique inválido."
      }
    };
  }

  const config = getPagarConfig();

  if (!config.configured) {
    return {
      status: 503,
      body: {
        success: false,
        code: "PAGAR_NOT_CONFIGURED",
        message:
          "Integração Pagar não está configurada no servidor."
      }
    };
  }

  const reference =
    String(body.reference || "").trim() ||
    makeReference("PAGAR-TOPUP");

  /*
   * Primeiro criamos o registo local.
   * O saldo MZN continua intocado.
   */
  const existing = await sql`
    SELECT
      id,
      reference,
      amount,
      status
    FROM transactions
    WHERE reference = ${reference}
    AND type = 'DEPOSIT_MZN'
    AND asset = 'MZN'
    LIMIT 1
  `;

  if (existing.length) {
    return {
      status: 200,
      body: {
        success: true,
        reference:
          existing[0].reference,
        amount:
          Number(existing[0].amount),
        status:
          existing[0].status,
        message:
          "Top-up já existe no sistema."
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

  const pagarBody = {
    reference,
    amountMzn: amount,
    method,
    paymentPhone
  };

  try {
    const pagarResponse =
      await pagarPost(
        "/wallet/topups",
        pagarBody,
        `topup:${reference}`
      );

    const pagarStatus =
      extractPagarStatus(pagarResponse);

    /*
     * Nunca consideramos 202 como dinheiro recebido.
     */
    if (pagarStatus === "PAID") {
      const confirmed =
        await confirmPagarTreasuryTopup({
          reference
        });

      return {
        status: confirmed.status,
        body: {
          ...confirmed.body,
          pagar: pagarResponse
        }
      };
    }

    if (
      pagarStatus === "FAILED" ||
      pagarStatus === "CANCELLED"
    ) {
      await sql`
        UPDATE transactions
        SET status = 'FAILED'
        WHERE reference = ${reference}
        AND type = 'DEPOSIT_MZN'
        AND asset = 'MZN'
        AND status = 'PENDING'
      `;

      return {
        status: 200,
        body: {
          success: true,
          status: "FAILED",
          reference,
          amount,
          pagar_status: pagarStatus,
          message:
            "Pagar recusou ou cancelou o top-up. O saldo MZN não foi aumentado."
        }
      };
    }

    return {
      status: 200,
      body: {
        success: true,
        status: "PENDING",
        reference,
        amount,
        method,
        payment_phone:
          paymentPhone,
        pagar_status:
          pagarStatus || "PENDING",
        pagar: pagarResponse,
        message:
          "Top-up enviado para Pagar. O saldo só será creditado quando o estado real for PAID."
      }
    };
  } catch (error) {
    /*
     * Não apagamos o PENDING.
     *
     * Isto permite repetir a consulta pela mesma
     * referência sem criar outro crédito.
     */
    return {
      status: 502,
      body: {
        success: false,
        code: "PAGAR_REQUEST_FAILED",
        reference,
        message:
          "Não foi possível concluir a comunicação com Pagar. O depósito permanece PENDING e o saldo não foi alterado.",
        detail:
          String(
            error?.message ||
              "Erro desconhecido."
          )
      }
    };
  }
}

/* =========================================================
   PAGAR — CONSULTAR TOP-UP
========================================================= */

async function confirmPagarTreasuryTopup(body) {
  const reference = String(
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

  const local = await sql`
    SELECT
      id,
      amount,
      reference,
      status
    FROM transactions
    WHERE reference = ${reference}
    AND type = 'DEPOSIT_MZN'
    AND asset = 'MZN'
    LIMIT 1
  `;

  if (!local.length) {
    return {
      status: 404,
      body: {
        success: false,
        message:
          "Top-up Pagar não encontrado no sistema."
      }
    };
  }

  const transaction = local[0];

  if (
    transaction.status === "COMPLETED"
  ) {
    return {
      status: 200,
      body: {
        success: true,
        status: "COMPLETED",
        already_confirmed: true,
        reference,
        amount:
          Number(transaction.amount),
        message:
          "Top-up já confirmado anteriormente."
      }
    };
  }

  if (
    transaction.status !== "PENDING"
  ) {
    return {
      status: 200,
      body: {
        success: true,
        status:
          transaction.status,
        reference,
        amount:
          Number(transaction.amount),
        message:
          "O depósito já não está PENDING."
      }
    };
  }

  let pagarResponse;

  try {
    pagarResponse =
      await pagarGet(
        `/wallet/topups/by-reference/${encodeURIComponent(
          reference
        )}`
      );
  } catch (error) {
    return {
      status: 502,
      body: {
        success: false,
        code: "PAGAR_STATUS_FAILED",
        reference,
        message:
          "Não foi possível consultar o estado real do top-up na Pagar.",
        detail:
          String(
            error?.message ||
              "Erro desconhecido."
          )
      }
    };
  }

  const pagarStatus =
    extractPagarStatus(
      pagarResponse
