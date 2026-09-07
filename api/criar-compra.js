import { neon } from "@neondatabase/serverless";
import {
  createHmac,
  timingSafeEqual,
  randomUUID
} from "node:crypto";

import {
  processAdminPurchaseToBinanceInternal
} from "./admin-withdrawal-process.js";

/* =========================================================
   CONFIGURAÇÃO USDTMZ
   ========================================================= */

const RATE_MZN_PER_USDT = 64;

const MIN_MZN = 64;
const MAX_MZN = 40000;

const ALLOWED_PAYMENT_METHODS = [
  "MPESA",
  "EMOLA"
];

const PAGAR_BASE_URL = (
  process.env.PAGAR_BASE_URL ||
  "https://api.pagar.co.mz/api/v1"
).replace(/\/+$/, "");

const PAGAR_STATUSES = [
  "PENDING",
  "PROCESSING",
  "PAID",
  "CANCELLED",
  "FAILED",
  "RECONCILIATION_REQUIRED"
];

/* =========================================================
   DATABASE
   ========================================================= */

function getDatabaseUrl() {
  return (
    process.env.URL_DO_BANCO_DE_DADOS ||
    process.env.POSTGRES_URL ||
    process.env.DATABASE_URL ||
    process.env.POSTGRES_URL_NON_POOLING ||
    process.env.DATABASE_URL_UNPOOLED
  );
}

/* =========================================================
   HELPERS
   ========================================================= */

function normalizeText(value) {
  return String(value ?? "").trim();
}

function normalizePayment(value) {
  return normalizeText(value).toUpperCase();
}

function calculateUsdt(amountMzn) {
  return Number(
    (Number(amountMzn) / RATE_MZN_PER_USDT).toFixed(6)
  );
}

function createOrderId() {
  return `USDTMZ-${Date.now()}-${randomUUID()
    .replace(/-/g, "")
    .slice(0, 12)
    .toUpperCase()}`;
}

function getHeader(req, name) {
  const value = req.headers?.[name];

  if (Array.isArray(value)) {
    return String(value[0] || "");
  }

  return String(value || "");
}

function getErrorMessage(error) {
  if (!error) {
    return "Erro desconhecido.";
  }

  return (
    error.message ||
    error.error ||
    error.detail ||
    String(error)
  );
}

/* =========================================================
   HMAC
   ========================================================= */

function safeCompare(a, b) {
  const A = Buffer.from(String(a));
  const B = Buffer.from(String(b));

  if (A.length !== B.length) {
    return false;
  }

  return timingSafeEqual(A, B);
}

function hmacHex(secret, payload) {
  return createHmac("sha256", secret)
    .update(payload)
    .digest("hex");
}

function hmacBase64(secret, payload) {
  return createHmac("sha256", secret)
    .update(payload)
    .digest("base64");
}

/* =========================================================
   BODY
   ========================================================= */

async function readRawBody(req) {
  if (
    typeof req.body === "string"
  ) {
    return req.body;
  }

  if (
    req.body &&
    typeof req.body === "object"
  ) {
    return JSON.stringify(req.body);
  }

  let body = "";

  for await (const chunk of req) {
    body += chunk;
  }

  return body;
}

function parseJsonBody(rawBody) {
  if (!rawBody) {
    return {};
  }

  try {
    return JSON.parse(rawBody);
  } catch {
    return {};
  }
}

/* =========================================================
   PAGAR — WEBHOOK SIGNATURE
   ========================================================= */

function verifyWebhookSignature(
  req,
  rawBody
) {
  const secret =
    process.env.PAGAR_WEBHOOK_SECRET;

  if (!secret) {
    return false;
  }

  const received =
    getHeader(req, "x-pagar-signature") ||
    getHeader(req, "x-webhook-signature") ||
    getHeader(req, "x-signature") ||
    getHeader(req, "Pagar-Signature");

  if (!received) {
    return false;
  }

  const clean =
    received
      .replace(/^sha256=/i, "")
      .trim();

  const expectedHex =
    hmacHex(secret, rawBody);

  const expectedBase64 =
    hmacBase64(secret, rawBody);

  return (
    safeCompare(clean, expectedHex) ||
    safeCompare(clean, expectedBase64)
  );
}

/* =========================================================
   PAGAR — EXTRAIR DADOS
   ========================================================= */

function getWebhookEventId(body) {
  return normalizeText(
    body?.event_id ||
    body?.eventId ||
    body?.id ||
    body?.data?.event_id ||
    body?.data?.eventId
  );
}

function getPaymentId(body) {
  return normalizeText(
    body?.payment_id ||
    body?.paymentId ||
    body?.payment?.id ||
    body?.data?.payment_id ||
    body?.data?.paymentId ||
    body?.data?.payment?.id
  );
}

function getReference(body) {
  return normalizeText(
    body?.reference ||
    body?.payment?.reference ||
    body?.data?.reference ||
    body?.data?.payment?.reference
  );
}

function getPaymentStatus(body) {
  const value =
    body?.status ||
    body?.payment_status ||
    body?.paymentStatus ||
    body?.payment?.status ||
    body?.data?.status ||
    body?.data?.payment_status ||
    body?.data?.paymentStatus ||
    body?.data?.payment?.status;

  return normalizeText(value).toUpperCase();
}

/* =========================================================
   PAGAR API
   ========================================================= */

async function pagarRequest(
  path,
  options = {}
) {
  const apiKey =
    process.env.PAGAR_API_KEY;

  if (!apiKey) {
    throw new Error(
      "PAGAR_API_KEY não configurada."
    );
  }

  const response =
    await fetch(
      `${PAGAR_BASE_URL}${path}`,
      {
        ...options,

        headers: {
          Accept: "application/json",
          "Content-Type":
            "application/json",

          Authorization:
            `Bearer ${apiKey}`,

          ...options.headers
        }
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
    throw new Error(
      `Pagar HTTP ${response.status}: ${
        data?.message ||
        data?.error ||
        data?.detail ||
        text ||
        "erro desconhecido"
      }`
    );
  }

  return data;
}

/* =========================================================
   CRIAR PAGAMENTO PAGAR
   ========================================================= */

async function createPagarPayment({
  orderId,
  name,
  phone,
  amountMzn,
  paymentMethod
}) {
  const payload = {
    reference: orderId,

    amount: amountMzn,

    currency: "MZN",

    description:
      `Compra de USDT - ${orderId}`,

    customer: {
      name,
      phone
    },

    payment_method:
      paymentMethod
  };

  return pagarRequest(
    "/payments",
    {
      method: "POST",
      body: JSON.stringify(payload)
    }
  );
}

/* =========================================================
   EXTRAIR PAYMENT ID
   ========================================================= */

function extractPaymentId(data) {
  return normalizeText(
    data?.payment_id ||
    data?.paymentId ||
    data?.id ||
    data?.payment?.id ||
    data?.data?.payment_id ||
    data?.data?.paymentId ||
    data?.data?.id ||
    data?.data?.payment?.id
  );
}

/* =========================================================
   PROCESSAR ORDEM PAID
   ========================================================= */

async function processPaidOrder(
  sql,
  orderId
) {
  const rows =
    await sql`
      SELECT
        order_id,
        operation,
        status,
        usdt_amount,
        blockchain_tx_hash
      FROM orders
      WHERE order_id = ${orderId}
      LIMIT 1
    `;

  if (!rows.length) {
    throw new Error(
      "Ordem não encontrada."
    );
  }

  const order = rows[0];

  if (order.blockchain_tx_hash) {
    return {
      status: "COMPLETED",
      tx_hash:
        order.blockchain_tx_hash
    };
  }

  if (
    String(order.operation || "")
      .toUpperCase() !==
    "BUY_USDT_ADMIN"
  ) {
    throw new Error(
      "Operação da ordem inválida."
    );
  }

  return processAdminPurchaseToBinanceInternal(
    orderId
  );
}

/* =========================================================
   WEBHOOK PAGAR
   ========================================================= */

async function handleWebhook(
  req,
  res,
  sql,
  rawBody
) {
  if (
    !verifyWebhookSignature(
      req,
      rawBody
    )
  ) {
    return res.status(401).json({
      success: false,
      message:
        "Assinatura do webhook inválida."
    });
  }

  const body =
    parseJsonBody(rawBody);

  const eventId =
    getWebhookEventId(body);

  const paymentId =
    getPaymentId(body);

  const reference =
    getReference(body);

  const pagarStatus =
    getPaymentStatus(body);

  if (!eventId) {
    return res.status(400).json({
      success: false,
      message:
        "event_id não informado."
    });
  }

  if (!reference) {
    return res.status(400).json({
      success: false,
      message:
        "Referência da ordem não encontrada.",
      event_id: eventId
    });
  }

  /* =======================================================
     IDEMPOTÊNCIA
     ======================================================= */

  const existing =
    await sql`
      SELECT
        event_id
      FROM pagar_webhook_events
      WHERE event_id = ${eventId}
      LIMIT 1
    `;

  if (existing.length) {
    return res.status(200).json({
      success: true,
      duplicate: true,
      event_id: eventId,
      message:
        "Evento já processado."
    });
  }

  /* =======================================================
     LOCALIZAR ORDEM
     ======================================================= */

  const orders =
    await sql`
      SELECT
        id,
        order_id,
        status,
        operation,
        pagar_payment_id,
        pagar_event_id,
        blockchain_tx_hash
      FROM orders
      WHERE order_id = ${reference}
      LIMIT 1
    `;

  if (!orders.length) {
    return res.status(404).json({
      success: false,
      message:
        "Ordem USDTMZ não encontrada.",
      reference,
      event_id: eventId
    });
  }

  const order = orders[0];

  /* =======================================================
     GUARDAR EVENTO
     ======================================================= */

  await sql`
    INSERT INTO pagar_webhook_events (
      event_id,
      event_type,
      payment_id,
      reference,
      payload,
      created_at
    )
    VALUES (
      ${eventId},
      ${pagarStatus || "UNKNOWN"},
      ${paymentId || null},
      ${reference},
      ${JSON.stringify(body)},
      NOW()
    )
    ON CONFLICT (event_id)
    DO NOTHING
  `;

  /* =======================================================
     JÁ TEM TX
     ======================================================= */

  if (order.blockchain_tx_hash) {
    await sql`
      UPDATE pagar_webhook_events
      SET processed_at = NOW()
      WHERE event_id = ${eventId}
    `;

    return res.status(200).json({
      success: true,
      duplicate: true,
      order_id:
        order.order_id,
      status:
        order.status,
      tx_hash:
        order.blockchain_tx_hash
    });
  }

  /* =======================================================
     GUARDAR PAYMENT ID
     ======================================================= */

  await sql`
    UPDATE orders
    SET
      pagar_payment_id =
        COALESCE(
          ${paymentId || null},
          pagar_payment_id
        ),

      pagar_event_id =
        ${eventId},

      updated_at = NOW()

    WHERE order_id = ${reference}
  `;

  /* =======================================================
     PAID
     ======================================================= */

  if (pagarStatus === "PAID") {
    await sql`
      UPDATE orders
      SET
        status = 'PAID',
        updated_at = NOW()
      WHERE order_id = ${reference}
      AND (
        blockchain_tx_hash IS NULL
        OR blockchain_tx_hash = ''
      )
    `;

    try {
      const transfer =
        await processPaidOrder(
          sql,
          reference
        );

      await sql`
        UPDATE pagar_webhook_events
        SET processed_at = NOW()
        WHERE event_id = ${eventId}
      `;

      return res.status(200).json({
        success: true,
        payment_status: "PAID",

        order_status:
          transfer?.body?.status ||
          transfer?.status ||
          "PROCESSING",

        order_id:
          reference,

        tx_hash:
          transfer?.body?.tx_hash ||
          transfer?.tx_hash ||
          null,

        message:
          transfer?.body?.message ||
          transfer?.message ||
          "Pagamento confirmado."
      });
    } catch (error) {
      console.error(
        "PAGAR PAID -> BINANCE ERROR:",
        error
      );

      /*
       * O pagamento foi confirmado.
       * Não marcamos como FAILED porque
       * pode ter ocorrido broadcast.
       */

      await sql`
        UPDATE orders
        SET
          status = 'PROCESSING',
          updated_at = NOW()
        WHERE order_id = ${reference}
        AND (
          blockchain_tx_hash IS NULL
          OR blockchain_tx_hash = ''
        )
      `;

      await sql`
        UPDATE pagar_webhook_events
        SET processed_at = NOW()
        WHERE event_id = ${eventId}
      `;

      return res.status(202).json({
        success: true,
        payment_status: "PAID",
        order_status: "PROCESSING",
        order_id: reference,
        requires_reconciliation: true,
        message:
          "Pagamento confirmado. Transferência USDT requer processamento."
      });
    }
  }

  /* =======================================================
     CANCELLED
     ======================================================= */

  if (
    pagarStatus === "CANCELLED"
  ) {
    await sql`
      UPDATE orders
      SET
        status = 'CANCELLED',
        updated_at = NOW()
      WHERE order_id = ${reference}
      AND (
        blockchain_tx_hash IS NULL
        OR blockchain_tx_hash = ''
      )
    `;

    await sql`
      UPDATE pagar_webhook_events
      SET processed_at = NOW()
      WHERE event_id = ${eventId}
    `;

    return res.status(200).json({
      success: true,
      payment_status: "CANCELLED",
      order_status: "CANCELLED",
      order_id: reference
    });
  }

  /* =======================================================
     FAILED
     ======================================================= */

  if (
    pagarStatus === "FAILED"
  ) {
    await sql`
      UPDATE orders
      SET
        status = 'FAILED',
        updated_at = NOW()
      WHERE order_id = ${reference}
      AND (
        blockchain_tx_hash IS NULL
        OR blockchain_tx_hash = ''
      )
    `;

    await sql`
      UPDATE pagar_webhook_events
      SET processed_at = NOW()
      WHERE event_id = ${eventId}
    `;

    return res.status(200).json({
      success: true,
      payment_status: "FAILED",
      order_status: "FAILED",
      order_id: reference
    });
  }

  /* =======================================================
     PENDING / PROCESSING
     ======================================================= */

  const safeStatus =
    PAGAR_STATUSES.includes(
      pagarStatus
    )
      ? pagarStatus
      : "PROCESSING";

  await sql`
    UPDATE orders
    SET
      status = ${safeStatus},
      updated_at = NOW()
    WHERE order_id = ${reference}
    AND (
      blockchain_tx_hash IS NULL
      OR blockchain_tx_hash = ''
    )
  `;

  await sql`
    UPDATE pagar_webhook_events
    SET processed_at = NOW()
    WHERE event_id = ${eventId}
  `;

  return res.status(200).json({
    success: true,
    payment_status:
      pagarStatus || "PROCESSING",
    order_status:
      safeStatus,
    order_id:
      reference
  });
}

/* =========================================================
   CONSULTAR PAGAMENTO NO PAGAR
   ========================================================= */

async function getPagarPaymentStatus(
  paymentId
) {
  return pagarRequest(
    `/payments/${encodeURIComponent(
      paymentId
    )}`,
    {
      method: "GET"
    }
  );
}

/* =========================================================
   STATUS MANUAL
   ========================================================= */

async function handleStatusCheck(
  req,
  res,
  sql
) {
  const apiSecret =
    process.env.PAGAR_SIGNING_SECRET;

  if (!apiSecret) {
    return res.status(500).json({
      success: false,
      message:
        "PAGAR_SIGNING_SECRET não configurada."
    });
  }

  const received =
    getHeader(
      req,
      "x-pagar-secret"
    );

  if (
    !received ||
    !safeCompare(
      received,
      apiSecret
    )
  ) {
    return res.status(401).json({
      success: false,
      message:
        "Não autorizado."
    });
  }

  const orderId =
    normalizeText(
      req.query?.order_id ||
      req.query?.orderId
    );

  if (!orderId) {
    return res.status(400).json({
      success: false,
      message:
        "order_id é obrigatório."
    });
  }

  const rows =
    await sql`
      SELECT
        order_id,
        status,
        pagar_payment_id,
        blockchain_tx_hash
      FROM orders
      WHERE order_id = ${orderId}
      LIMIT 1
    `;

  if (!rows.length) {
    return res.status(404).json({
      success: false,
      message:
        "Ordem não encontrada."
    });
  }

  const order = rows[0];

  if (order.blockchain_tx_hash) {
    return res.status(200).json({
      success: true,
      order_id:
        order.order_id,
      status:
        order.status,
      tx_hash:
        order.blockchain_tx_hash
    });
  }

  if (!order.pagar_payment_id) {
    return res.status(409).json({
      success: false,
      message:
        "A ordem ainda não possui pagar_payment_id."
    });
  }

  const payment =
    await getPagarPaymentStatus(
      order.pagar_payment_id
    );

  const status =
    getPaymentStatus(payment);

  if (status === "PAID") {
    await sql`
      UPDATE orders
      SET
        status = 'PAID',
        updated_at = NOW()
      WHERE order_id = ${orderId}
      AND (
        blockchain_tx_hash IS NULL
        OR blockchain_tx_hash = ''
      )
    `;

    try {
      const transfer =
        await processPaidOrder(
          sql,
          orderId
        );

      return res.status(200).json({
        success: true,
        payment_status: "PAID",

        order_status:
          transfer?.body?.status ||
          transfer?.status ||
          "PROCESSING",

        order_id:
          orderId,

        tx_hash:
          transfer?.body?.tx_hash ||
          transfer?.tx_hash ||
          null
      });
    } catch (error) {
      console.error(
        "PAGAR STATUS -> BINANCE ERROR:",
        error
      );

      await sql`
        UPDATE orders
        SET
          status = 'PROCESSING',
          updated_at = NOW()
        WHERE order_id = ${orderId}
        AND (
          blockchain_tx_hash IS NULL
          OR blockchain_tx_hash = ''
        )
      `;

      return res.status(202).json({
        success: true,
        payment_status: "PAID",
        order_status: "PROCESSING",
        order_id: orderId,
        requires_reconciliation: true,
        message:
          "Pagamento confirmado. Transferência requer processamento."
      });
    }
  }

  const finalStatus =
    PAGAR_STATUSES.includes(status)
      ? status
      : "PROCESSING";

  await sql`
    UPDATE orders
    SET
      status = ${finalStatus},
      updated_at = NOW()
    WHERE order_id = ${orderId}
    AND (
      blockchain_tx_hash IS NULL
      OR blockchain_tx_hash = ''
    )
  `;

  return res.status(200).json({
    success: true,
    payment_status:
      status || "PROCESSING",
    order_status:
      finalStatus,
    order_id:
      orderId
  });
}

/* =========================================================
   CRIAR COMPRA
   ========================================================= */

async function createPurchase(
  req,
  res,
  sql
) {
  const body =
    req.body &&
    typeof req.body === "object"
      ? req.body
      : parseJsonBody(
          await readRawBody(req)
        );

  const name =
    normalizeText(
      body.name
    );

  const phone =
    normalizeText(
      body.phone
    );

  const paymentMethod =
    normalizePayment(
      body.payment ||
      body.payment_method ||
      body.method
    );

  const amountMzn =
    Number(
      body.amount ??
      body.amount_mzn ??
      body.valor
    );

  /* =======================================================
     VALIDAÇÕES
     ======================================================= */

  if (!name) {
    return res.status(400).json({
      success: false,
      message:
        "Nome é obrigatório."
    });
  }

  if (!phone) {
    return res.status(400).json({
      success: false,
      message:
        "Telefone é obrigatório."
    });
  }

  if (
    !Number.isFinite(amountMzn)
  ) {
    return res.status(400).json({
      success: false,
      message:
        "Valor em MZN inválido."
    });
  }

  if (
    amountMzn < MIN_MZN
  ) {
    return res.status(400).json({
      success: false,
      message:
        `O valor mínimo é ${MIN_MZN} MZN.`
    });
  }

  if (
    amountMzn > MAX_MZN
  ) {
    return res.status(400).json({
      success: false,
      message:
        `O valor máximo é ${MAX_MZN} MZN.`
    });
  }

  if (
    !ALLOWED_PAYMENT_METHODS.includes(
      paymentMethod
    )
  ) {
    return res.status(400).json({
      success: false,
      message:
        "Método de pagamento inválido. Use MPESA ou EMOLA."
    });
  }

  /* =======================================================
     CÁLCULO
     ======================================================= */

  const usdtAmount =
    calculateUsdt(
      amountMzn
    );

  const orderId =
    createOrderId();

  /* =======================================================
     CRIAR ORDEM NO NEON
     ======================================================= */

  let created;

  try {
    created =
      await sql`
        INSERT INTO orders (
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
          updated_at
        )
        VALUES (
          ${orderId},
          ${name},
          ${phone},
          'BUY_USDT_ADMIN',
          ${paymentMethod},
          ${amountMzn},
          ${usdtAmount},
          ${RATE_MZN_PER_USDT},
          'PENDING',
          NOW(),
          NOW()
        )
        RETURNING
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
          created_at
      `;
  } catch (error) {
    console.error(
      "DATABASE CREATE ORDER ERROR:",
      error
    );

    return res.status(500).json({
      success: false,
      message:
        "Não foi possível criar a ordem no banco de dados.",
      detail:
        getErrorMessage(error)
    });
  }

  if (!created?.length) {
    return res.status(500).json({
      success: false,
      message:
        "A ordem não foi criada."
    });
  }

  const order =
    created[0];

  /* =======================================================
     CRIAR PAGAMENTO NO PAGAR
     ======================================================= */

  try {
    const pagar =
      await createPagarPayment({
        orderId:
          order.order_id,

        name,

        phone,

        amountMzn,

        paymentMethod
      });

    const paymentId =
      extractPaymentId(
        pagar
      );

    /*
     * Se o Pagar não devolver ID,
     * não fingimos que o pagamento foi criado.
     */

    if (!paymentId) {
      console.error(
        "PAGAR RESPONSE WITHOUT PAYMENT ID:",
        pagar
      );

      await sql`
        UPDATE orders
        SET
          status = 'FAILED',
          updated_at = NOW()
        WHERE order_id = ${order.order_id}
        AND (
          blockchain_tx_hash IS NULL
          OR blockchain_tx_hash = ''
        )
      `;

      return res.status(502).json({
        success: false,
        message:
          "O Pagar respondeu sem payment_id.",
        order_id:
          order.order_id
      });
    }

    /* =====================================================
       ATUALIZAR ORDEM
       ===================================================== */

    await sql`
      UPDATE orders
      SET
        pagar_payment_id =
          ${paymentId},

        status = 'PROCESSING',

        updated_at = NOW()

      WHERE order_id =
        ${order.order_id}
    `;

    /* =====================================================
       RESPOSTA
       ===================================================== */

    return res.status(201).json({
      success: true,

      message:
        "Ordem criada e pagamento enviado ao Pagar.",

      order: {
        order_id:
          order.order_id,

        amount_mzn:
          Number(order.amount),

        usdt_amount:
          Number(order.usdt_amount),

        rate:
          Number(order.rate),

        payment:
          order.payment,

        status:
          "PROCESSING"
      },

      pagar: {
        payment_id:
          paymentId,

        data:
          pagar
      }
    });

  } catch (error) {
    console.error(
      "PAGAR CREATE PAYMENT ERROR:",
      error
    );

    /*
     * A ordem continua registrada no banco,
     * mas o pagamento não foi criado.
     */

    await sql`
      UPDATE orders
      SET
        status = 'FAILED',
        updated_at = NOW()
      WHERE order_id = ${order.order_id}
      AND (
        blockchain_tx_hash IS NULL
        OR blockchain_tx_hash = ''
      )
    `;

    return res.status(502).json({
      success: false,

      message:
        "A ordem foi criada, mas não foi possível criar o pagamento no Pagar.",

      order_id:
        order.order_id,

      detail:
        getErrorMessage(error)
    });
  }
}

/* =========================================================
   HANDLER PRINCIPAL
   ========================================================= */

export default async function handler(
  req,
  res
) {
  try {
    const databaseUrl =
      getDatabaseUrl();

    if (!databaseUrl) {
      return res.status(500).json({
        success: false,
        message:
          "Banco de dados não configurado."
      });
    }

    const sql =
      neon(databaseUrl);

    /* =====================================================
       WEBHOOK PAGAR
       ===================================================== */

    if (
      req.method === "POST" &&
      (
        getHeader(
          req,
          "x-pagar-signature"
        ) ||
        getHeader(
          req,
          "x-webhook-signature"
        ) ||
        getHeader(
          req,
          "x-signature"
        ) ||
        getHeader(
          req,
          "Pagar-Signature"
        )
      )
    ) {
      const rawBody =
        await readRawBody(req);

      return await handleWebhook(
        req,
        res,
        sql,
        rawBody
      );
    }

    /* =====================================================
       CONSULTAR STATUS
       ===================================================== */

    if (
      req.method === "GET" &&
      (
        req.query?.order_id ||
        req.query?.orderId
      )
    ) {
      return await handleStatusCheck(
        req,
        res,
        sql
      );
    }

    /* =====================================================
       CRIAR COMPRA
       ===================================================== */

    if (
      req.method === "POST"
    ) {
      return await createPurchase(
        req,
        res,
        sql
      );
    }

    /* =====================================================
       MÉTODO NÃO PERMITIDO
       ===================================================== */

    return res.status(405).json({
      success: false,
      message:
        "Método não permitido."
    });

  } catch (error) {
    console.error(
      "CREATE PURCHASE FATAL ERROR:",
      error
    );

    return res.status(500).json({
      success: false,
      message:
        "Erro interno ao processar a operação.",
      detail:
        getErrorMessage(error)
    });
  }
}
