import { neon } from "@neondatabase/serverless";
import {
  createHmac,
  createHash,
  randomBytes,
  randomUUID,
  timingSafeEqual
} from "node:crypto";

import {
  processAdminPurchaseToBinanceInternal
} from "./admin-withdrawal-process.js";

/* =========================================================
   VERCEL
   Precisamos do body bruto para validar o webhook da Pagar.
   ========================================================= */

export const config = {
  api: {
    bodyParser: false
  }
};

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
  process.env.PAGAR_API_BASE_URL ||
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

function safeCompare(a, b) {
  const A = Buffer.from(String(a));
  const B = Buffer.from(String(b));

  if (A.length !== B.length) {
    return false;
  }

  return timingSafeEqual(A, B);
}

/* =========================================================
   BODY RAW
   ========================================================= */

async function readRawBody(req) {
  if (Buffer.isBuffer(req.body)) {
    return req.body.toString("utf8");
  }

  if (typeof req.body === "string") {
    return req.body;
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
   PAGAR — POST ASSINADO
   Conforme documentação atual:
   timestamp
   nonce
   method
   pathname
   sha256(body)
   ========================================================= */

async function pagarPost(
  path,
  body,
  idempotencyKey
) {
  const apiKey =
    process.env.PAGAR_API_KEY;

  const signingSecret =
    process.env.PAGAR_SIGNING_SECRET;

  if (!apiKey) {
    throw new Error(
      "PAGAR_API_KEY não configurada."
    );
  }

  if (!signingSecret) {
    throw new Error(
      "PAGAR_SIGNING_SECRET não configurada."
    );
  }

  const url =
    `${PAGAR_BASE_URL}${path}`;

  const timestamp =
    Date.now().toString();

  const nonce =
    randomBytes(18).toString("base64url");

  const rawBody =
    JSON.stringify(body);

  const bodyHash =
    createHash("sha256")
      .update(rawBody)
      .digest("hex");

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

  const response =
    await fetch(url, {
      method: "POST",

      headers: {
        Accept: "application/json",
        "Content-Type": "application/json",

        Authorization:
          `Bearer ${apiKey}`,

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
    });

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
    const error = new Error(
      data?.message ||
      data?.error ||
      data?.detail ||
      text ||
      `Pagar HTTP ${response.status}`
    );

    error.status =
      response.status;

    error.code =
      data?.error || null;

    error.requestId =
      data?.requestId || null;

    throw error;
  }

  return data;
}

/* =========================================================
   PAGAR — GET
   ========================================================= */

async function pagarGet(path) {
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
        method: "GET",
        headers: {
          Accept: "application/json",
          Authorization:
            `Bearer ${apiKey}`
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
      data?.message ||
      data?.error ||
      data?.detail ||
      text ||
      `Pagar HTTP ${response.status}`
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

    title:
      "Compra de USDT",

    description:
      `Compra de USDT - ${orderId}`,

    amountMzn:
      amountMzn,

    method:
      paymentMethod,

    payerPhone:
      phone
  };

  /*
   * A mesma orderId produz sempre a mesma
   * Idempotency-Key para esta tentativa.
   */
  const idempotencyKey =
    `payment:${orderId}`;

  return pagarPost(
    "/payments",
    payload,
    idempotencyKey
  );
}

/* =========================================================
   EXTRAIR PAYMENT
   ========================================================= */

function extractPayment(data) {
  return (
    data?.payment ||
    data?.data?.payment ||
    data
  );
}

function extractPaymentId(data) {
  const payment =
    extractPayment(data);

  return normalizeText(
    payment?.id ||
    data?.payment_id ||
    data?.paymentId ||
    data?.data?.payment_id ||
    data?.data?.paymentId
  );
}

function extractPaymentStatus(data) {
  const payment =
    extractPayment(data);

  return normalizeText(
    payment?.status ||
    data?.status ||
    data?.payment_status ||
    data?.paymentStatus
  ).toUpperCase();
}

/* =========================================================
   WEBHOOK — EVENT ID
   ========================================================= */

function getWebhookEventId(
  req,
  body
) {
  return normalizeText(
    getHeader(
      req,
      "pagar-event-id"
    ) ||
    body?.event_id ||
    body?.eventId ||
    body?.id
  );
}

/* =========================================================
   WEBHOOK — EVENT TYPE
   ========================================================= */

function getWebhookEventType(body) {
  return normalizeText(
    body?.type ||
    body?.event ||
    body?.event_type ||
    body?.eventType
  ).toLowerCase();
}

/* =========================================================
   WEBHOOK — PAYMENT
   ========================================================= */

function getWebhookPayment(body) {
  return (
    body?.payment ||
    body?.data?.payment ||
    body?.data ||
    body
  );
}

function getPaymentId(body) {
  const payment =
    getWebhookPayment(body);

  return normalizeText(
    payment?.id ||
    body?.payment_id ||
    body?.paymentId
  );
}

function getReference(body) {
  const payment =
    getWebhookPayment(body);

  return normalizeText(
    payment?.reference ||
    body?.reference ||
    body?.data?.reference
  );
}

function getPaymentStatus(body) {
  const payment =
    getWebhookPayment(body);

  return normalizeText(
    payment?.status ||
    body?.status ||
    body?.payment_status ||
    body?.paymentStatus
  ).toUpperCase();
}

/* =========================================================
   WEBHOOK — ASSINATURA PAGAR
   Formato oficial:
   Pagar-Signature:
   t=timestamp,v1=signature
   ========================================================= */

function verifyWebhookSignature(
  req,
  rawBody
) {
  const secret =
    process.env.PAGAR_WEBHOOK_SECRET;

  if (!secret) {
    console.error(
      "PAGAR_WEBHOOK_SECRET não configurada."
    );

    return false;
  }

  const eventId =
    getHeader(
      req,
      "pagar-event-id"
    );

  if (!eventId) {
    return false;
  }

  const signatureHeader =
    getHeader(
      req,
      "pagar-signature"
    );

  if (!signatureHeader) {
    return false;
  }

  const parts =
    signatureHeader
      .split(",")
      .map(part => {
        const index =
          part.indexOf("=");

        if (index === -1) {
          return null;
        }

        return [
          part.slice(0, index).trim(),
          part.slice(index + 1).trim()
        ];
      })
      .filter(Boolean);

  const parsed =
    Object.fromEntries(parts);

  const timestamp =
    parsed.t;

  const received =
    parsed.v1;

  if (
    !timestamp ||
    !received
  ) {
    return false;
  }

  if (
    !/^\d+$/.test(timestamp)
  ) {
    return false;
  }

  if (
    !/^[a-f0-9]{64}$/i.test(received)
  ) {
    return false;
  }

  const timestampSeconds =
    Number(timestamp);

  if (
    !Number.isFinite(
      timestampSeconds
    )
  ) {
    return false;
  }

  /*
   * Rejeita webhooks antigos.
   */
  if (
    Math.abs(
      Date.now() / 1000 -
      timestampSeconds
    ) > 300
  ) {
    return false;
  }

  const expected =
    createHmac(
      "sha256",
      secret
    )
      .update(
        `${timestamp}.${rawBody}`
      )
      .digest("hex");

  return safeCompare(
    received.toLowerCase(),
    expected.toLowerCase()
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

  const order =
    rows[0];

  if (
    order.blockchain_tx_hash
  ) {
    return {
      status: "COMPLETED",

      tx_hash:
        order.blockchain_tx_hash
    };
  }

  if (
    String(
      order.operation || ""
    ).toUpperCase() !==
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

  let body;

  try {
    body =
      JSON.parse(rawBody);
  } catch {
    return res.status(400).json({
      success: false,
      message:
        "Webhook JSON inválido."
    });
  }

  const eventId =
    getWebhookEventId(
      req,
      body
    );

  const eventType =
    getWebhookEventType(
      body
    );

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
        "Pagar-Event-Id não informado."
    });
  }

  if (!reference) {
    return res.status(400).json({
      success: false,
      message:
        "Referência da ordem não encontrada.",
      event_id:
        eventId
    });
  }

  /* =======================================================
     IDEMPOTÊNCIA DO WEBHOOK
     ======================================================= */

  const existing =
    await sql`
      SELECT event_id
      FROM pagar_webhook_events
      WHERE event_id = ${eventId}
      LIMIT 1
    `;

  if (existing.length) {
    return res.status(200).json({
      success: true,
      duplicate: true,
      event_id:
        eventId,
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
      event_id:
        eventId
    });
  }

  const order =
    orders[0];

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
      ${eventType || "UNKNOWN"},
      ${paymentId || null},
      ${reference},
      ${JSON.stringify(body)},
      NOW()
    )
    ON CONFLICT (event_id)
    DO NOTHING
  `;

  /* =======================================================
     JÁ TEM TX HASH
     ======================================================= */

  if (
    order.blockchain_tx_hash
  ) {
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

      updated_at =
        NOW()

    WHERE order_id =
      ${reference}
  `;

  /* =======================================================
     SUCESSO
     ======================================================= */

  const paymentSucceeded =
    eventType ===
      "payment.succeeded" ||
    pagarStatus === "PAID";

  if (paymentSucceeded) {
    await sql`
      UPDATE orders
      SET
        status = 'PAID',
        updated_at = NOW()
      WHERE order_id =
        ${reference}
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
        payment_status:
          "PAID",

        event_type:
          eventType,

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
       *
       * Nunca marcamos como FAILED
       * simplesmente porque a transferência
       * USDT falhou ou ficou inconclusiva.
       */

      await sql`
        UPDATE orders
        SET
          status = 'PROCESSING',
          updated_at = NOW()
        WHERE order_id =
          ${reference}
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

        payment_status:
          "PAID",

        order_status:
          "PROCESSING",

        order_id:
          reference,

        requires_reconciliation:
          true,

        message:
          "Pagamento confirmado. A transferência USDT requer processamento."
      });
    }
  }

  /* =======================================================
     PAGAMENTO FALHOU
     ======================================================= */

  const paymentFailed =
    eventType ===
      "payment.failed" ||
    pagarStatus === "FAILED";

  if (paymentFailed) {
    await sql`
      UPDATE orders
      SET
        status = 'FAILED',
        updated_at = NOW()
      WHERE order_id =
        ${reference}
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
        "FAILED",
      order_status:
        "FAILED",
      order_id:
        reference
    });
  }

  /* =======================================================
     PAGAMENTO CANCELADO
     ======================================================= */

  const paymentCancelled =
    pagarStatus ===
      "CANCELLED";

  if (paymentCancelled) {
    await sql`
      UPDATE orders
      SET
        status = 'CANCELLED',
        updated_at = NOW()
      WHERE order_id =
        ${reference}
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
        "CANCELLED",
      order_status:
        "CANCELLED",
      order_id:
        reference
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
      status =
        ${safeStatus},

      updated_at =
        NOW()

    WHERE order_id =
      ${reference}

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
      pagarStatus ||
      "PROCESSING",

    order_status:
      safeStatus,

    order_id:
      reference
  });
}

/* =========================================================
   CONSULTAR PAGAMENTO
   ========================================================= */

async function getPagarPaymentStatus(
  paymentId
) {
  return pagarGet(
    `/payments/${encodeURIComponent(
      paymentId
    )}`
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
      WHERE order_id =
        ${orderId}
      LIMIT 1
    `;

  if (!rows.length) {
    return res.status(404).json({
      success: false,
      message:
        "Ordem não encontrada."
    });
  }

  const order =
    rows[0];

  if (
    order.blockchain_tx_hash
  ) {
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

  if (
    !order.pagar_payment_id
  ) {
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
    extractPaymentStatus(
      payment
    );

  if (
    status === "PAID"
  ) {
    await sql`
      UPDATE orders
      SET
        status = 'PAID',
        updated_at = NOW()
      WHERE order_id =
        ${orderId}
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

        payment_status:
          "PAID",

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
        WHERE order_id =
          ${orderId}
        AND (
          blockchain_tx_hash IS NULL
          OR blockchain_tx_hash = ''
        )
      `;

      return res.status(202).json({
        success: true,

        payment_status:
          "PAID",

        order_status:
          "PROCESSING",

        order_id:
          orderId,

        requires_reconciliation:
          true,

        message:
          "Pagamento confirmado. Transferência requer processamento."
      });
    }
  }

  const finalStatus =
    PAGAR_STATUSES.includes(
      status
    )
      ? status
      : "PROCESSING";

  await sql`
    UPDATE orders
    SET
      status =
        ${finalStatus},

      updated_at =
        NOW()

    WHERE order_id =
      ${orderId}

    AND (
      blockchain_tx_hash IS NULL
      OR blockchain_tx_hash = ''
    )
  `;

  return res.status(200).json({
    success: true,

    payment_status:
      status ||
      "PROCESSING",

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
  const rawBody =
    await readRawBody(req);

  const body =
    parseJsonBody(
      rawBody
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
    !Number.isFinite(
      amountMzn
    )
  ) {
    return res.status(400).json({
      success: false,
      message:
        "Valor em MZN inválido."
    });
  }

  /*
   * Pagar exige valor inteiro.
   */
  if (
    !Number.isInteger(
      amountMzn
    )
  ) {
    return res.status(400).json({
      success: false,
      message:
        "O valor em MZN deve ser inteiro."
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
     CÁLCULO USDT
     ======================================================= */

  const usdtAmount =
    calculateUsdt(
      amountMzn
    );

  const orderId =
    createOrderId();

  /* =======================================================
     CRIAR ORDEM
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

  if (
    !created?.length
  ) {
    return res.status(500).json({
      success: false,
      message:
        "A ordem não foi criada."
    });
  }

  const order =
    created[0];

  /* =======================================================
     CRIAR PAGAMENTO PAGAR
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

    const payment =
      extractPayment(
        pagar
      );

    const paymentId =
      extractPaymentId(
        pagar
      );

    const paymentStatus =
      extractPaymentStatus(
        pagar
      );

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
        WHERE order_id =
          ${order.order_id}
      `;

      return res.status(502).json({
        success: false,

        message:
          "A Pagar respondeu sem payment_id.",

        order_id:
          order.order_id
      });
    }

    /* =====================================================
       ATUALIZAR ORDEM
       ===================================================== */

    const safeInitialStatus =
      PAGAR_STATUSES.includes(
        paymentStatus
      )
        ? paymentStatus
        : "PROCESSING";

    await sql`
      UPDATE orders
      SET
        pagar_payment_id =
          ${paymentId},

        status =
          ${safeInitialStatus},

        updated_at =
          NOW()

      WHERE order_id =
        ${order.order_id}
    `;

    /* =====================================================
       RESPOSTA
       ===================================================== */

    return res.status(202).json({
      success: true,

      message:
        "Pagamento enviado para a Pagar. Aguarde a confirmação.",

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
          safeInitialStatus
      },

      pagar: {
        payment_id:
          paymentId,

        status:
          paymentStatus ||
          safeInitialStatus,

        data:
          payment
      }
    });

  } catch (error) {
    console.error(
      "PAGAR CREATE PAYMENT ERROR:",
      error
    );

    /*
     * IMPORTANTE:
     *
     * 5xx / timeout pode significar que a Pagar
     * recebeu a operação mas a resposta foi perdida.
     *
     * Por segurança não apagamos a ordem e não
     * criamos outra automaticamente.
     */

    const uncertain =
      Number(error?.status || 0) >= 500 ||
      !error?.status;

    await sql`
      UPDATE orders
      SET
        status =
          ${uncertain
            ? "RECONCILIATION_REQUIRED"
            : "FAILED"},

        updated_at =
          NOW()

      WHERE order_id =
        ${order.order_id}
    `;

    return res.status(
      uncertain ? 202 : 502
    ).json({
      success: false,

      message:
        uncertain
          ? "A tentativa de pagamento ficou inconclusiva. A operação não será repetida automaticamente."
          : "A Pagar recusou a criação do pagamento.",

      order_id:
        order.order_id,

      status:
        uncertain
          ? "RECONCILIATION_REQUIRED"
          : "FAILED",

      detail:
        getErrorMessage(error),

      request_id:
        error?.requestId ||
        null
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
       WEBHOOK
       ===================================================== */

    if (
      req.method === "POST" &&
      getHeader(
        req,
        "pagar-event-id"
      ) &&
      getHeader(
        req,
        "pagar-signature"
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

Agora atenção às variáveis da Vercel

No projeto, precisamos ter estas quatro:

PAGAR_API_BASE_URL
PAGAR_API_KEY
PAGAR_SIGNING_SECRET
PAGAR_WEBHOOK_SECRET

A documentação atual confirma exatamente essas credenciais e explica que "PAGAR_SIGNING_SECRET" assina os "POST", enquanto "PAGAR_WEBHOOK_SECRET" valida os webhooks.

Não me envie os valores das chaves. Apenas confirme se as quatro existem na Vercel.

O primeiro teste

Depois de substituir o arquivo:

1. Deploy na Vercel.
2. Abra o Admin.
3. Coloque:
   - Nome: qualquer nome
   - Telefone de teste da Pagar
   - 640 MZN
   - M-Pesa
4. Clique CRIAR PAGAMENTO.

O resultado esperado agora é aproximadamente:

640 MZN → 10 USDT → Pagar → PROCESSING

Não deve aparecer mais o antigo payload "amount/payment_method/customer".

A própria Pagar documenta que uma criação normal retorna HTTP 202 e estado inicialmente "PENDING" ou "PROCESSING"; só devemos considerar o pagamento concluído quando houver "payment.succeeded"/"PAID".

Não faça ainda o envio para Binance. Primeiro vamos confirmar que o pagamento M-Pesa/e-Mola está sendo criado corretamente. Depois fechamos o webhook e a liquidez.

"Documentação oficial da Pagar API" (https://pagar.co.mz/docs?utm_source=chatgpt.com)
