import { neon } from "@neondatabase/serverless";
import { createHmac, timingSafeEqual, randomUUID } from "node:crypto";
import { processAdminPurchaseToBinanceInternal } from "./admin-withdrawal-process.js";

const RATE_MZN_PER_USDT = 64;

const MIN_MZN = 64;
const MAX_MZN = 40000;

const ALLOWED_PAYMENT_METHODS = [
  "MPESA",
  "EMOLA"
];

const PAGAR_BASE_URL =
  process.env.PAGAR_BASE_URL ||
  "https://api.pagar.co.mz/api/v1";

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
  return String(value || "").trim();
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
    return value[0] || "";
  }

  return String(value || "");
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
  return createHmac(
    "sha256",
    secret
  )
    .update(payload)
    .digest("hex");
}

function hmacBase64(secret, payload) {
  return createHmac(
    "sha256",
    secret
  )
    .update(payload)
    .digest("base64");
}

/* =========================================================
   BODY
   ========================================================= */

async function readRawBody(req) {
  if (
    req.body &&
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
   PAGAR — ASSINATURA
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
    );

  if (!received) {
    return false;
  }

  const receivedClean =
    received
      .replace(/^sha256=/i, "")
      .trim();

  const expectedHex =
    hmacHex(
      secret,
      rawBody
    );

  const expectedBase64 =
    hmacBase64(
      secret,
      rawBody
    );

  return (
    safeCompare(
      receivedClean,
      expectedHex
    ) ||
    safeCompare(
      receivedClean,
      expectedBase64
    )
  );
}

/* =========================================================
   PAGAR — EXTRAÇÃO DE DADOS
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
   PAGAR — API
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
          "Content-Type":
            "application/json",
          Accept:
            "application/json",
          Authorization:
            `Bearer ${apiKey}`,
          ...options.headers
        }
      }
    );

  const text =
    await response.text();

  let data;

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
    throw new Error(
      `Pagar HTTP ${response.status}: ${
        data?.message ||
        data?.error ||
        text ||
        "erro desconhecido"
      }`
    );
  }

  return data;
}

/* =========================================================
   CRIAR PAGAMENTO
   ========================================================= */

async function createPagarPayment({
  orderId,
  name,
  phone,
  amountMzn,
  paymentMethod
}) {
  /*
   * O formato abaixo mantém a ordem USDTMZ
   * identificável no Pagar.
   *
   * Se a conta Pagar exigir campos adicionais,
   * eles devem ser configurados aqui,
   * sem colocar secrets no frontend.
   */

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
   ATUALIZAR ORDEM APÓS PAID
   ========================================================= */

async function processPaidOrder(
  sql,
  orderId
) {
  /*
   * Busca novamente para evitar processar
   * uma ordem inexistente.
   */
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
    String(order.operation || "")
      .toUpperCase() !==
    "BUY_USDT_ADMIN"
  ) {
    throw new Error(
      "Operação da ordem inválida."
    );
  }

  /*
   * A API 05 faz o claim PAID → PROCESSING.
   */
  const result =
    await processAdminPurchaseToBinanceInternal(
      orderId
    );

  return {
    status:
      result?.body?.status ||
      "PROCESSING",

    tx_hash:
      result?.body?.tx_hash ||
      null,

    message:
      result?.body?.message ||
      null
  };
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
    parseJsonBody(
      rawBody
    );

  const eventId =
    getWebhookEventId(
      body
    );

  const paymentId =
    getPaymentId(
      body
    );

  const reference =
    getReference(
      body
    );

  const pagarStatus =
    getPaymentStatus(
      body
    );

  if (!eventId) {
    return res.status(400).json({
      success: false,
      message:
        "event_id não informado."
    });
  }

  /*
   * Idempotência:
   * o mesmo evento não pode ser processado
   * duas vezes.
   */
  const existing =
    await sql`
      SELECT
        id,
        event_id,
        payment_id,
        reference,
        processed_at
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

  /*
   * Guarda o evento antes de processar.
   */
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
      ${reference || null},
      ${JSON.stringify(body)},
      NOW()
    )
    ON CONFLICT (event_id)
    DO NOTHING
  `;

  if (!reference) {
    return res.status(400).json({
      success: false,
      message:
        "Referência da ordem não encontrada.",
      event_id: eventId
    });
  }

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

  const order =
    orders[0];

  /*
   * Se o pagamento já foi concluído,
   * não repetir envio.
   */
  if (
    order.blockchain_tx_hash
  ) {
    await sql`
      UPDATE pagar_webhook_events
      SET
        processed_at = NOW()
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

  /*
   * Guarda o payment ID/evento.
   */
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
    WHERE order_id =
      ${reference}
  `;

  /*
   * =====================================================
   * PAID
   * =====================================================
   */
  if (
    pagarStatus === "PAID"
  ) {
    await sql`
      UPDATE orders
      SET
        status = 'PAID',
        updated_at = NOW()
      WHERE order_id =
        ${reference}
        AND (
          UPPER(status) IN (
            'PENDING',
            'PROCESSING',
            'PAID'
          )
        )
        AND (
          blockchain_tx_hash IS NULL
          OR blockchain_tx_hash = ''
        )
    `;

    let transfer;

    try {
      transfer =
        await processPaidOrder(
          sql,
          reference
        );
    } catch (error) {
      console.error(
        "PAGAR PAID → BINANCE ERROR:",
        error
      );

      /*
       * Não marcamos FAILED automaticamente.
       *
       * O pagamento foi confirmado, mas
       * o resultado blockchain pode ser
       * desconhecido.
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
        SET
          processed_at = NOW()
        WHERE event_id =
          ${eventId}
      `;

      return res.status(202).json({
        success: true,
        payment_status: "PAID",
        order_status: "PROCESSING",
        order_id: reference,
        message:
          "Pagamento confirmado. Transferência USDT para Binance requer processamento/reconciliação.",
        requires_reconciliation:
          true
      });
    }

    await sql`
      UPDATE pagar_webhook_events
      SET
        processed_at = NOW()
      WHERE event_id =
        ${eventId}
    `;

    return res.status(200).json({
      success: true,
      payment_status: "PAID",
      order_status:
        transfer.status,
      order_id: reference,
      tx_hash:
        transfer.tx_hash || null,
      message:
        transfer.message ||
        "Pagamento confirmado."
    });
  }

  /*
   * =====================================================
   * CANCELADO
   * =====================================================
   */
  if (
    pagarStatus === "CANCELLED"
  ) {
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
      SET
        processed_at = NOW()
      WHERE event_id =
        ${eventId}
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

  /*
   * =====================================================
   * FAILED
   * =====================================================
   */
  if (
    pagarStatus === "FAILED"
  ) {
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
      SET
        processed_at = NOW()
      WHERE event_id =
        ${eventId}
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

  /*
   * PENDING / PROCESSING / OUTROS
   */
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
    SET
      processed_at = NOW()
    WHERE event_id =
      ${eventId}
  `;

  return res.status(200).json({
    success: true,
    payment_status:
      pagarStatus,
    order_status:
      safeStatus,
    order_id:
      reference
  });
}

/* =========================================================
   VERIFICAR PAGAMENTO MANUALMENTE
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
    getPaymentStatus(
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
          transfer.status,
        order_id:
          orderId,
        tx_hash:
          transfer.tx_hash || null
      });
    } catch (error) {
      console.error(
        "PAGAR STATUS → BINANCE ERROR:",
        error
      );

      await sql`
        UPDATE orders
        SET
          status =
            'PROCESSING',
          updated_at =
            NOW()
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
        message:
          "Pagamento confirmado. Transferência requer reconciliação.",
        requires_reconciliation:
          true
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
      status,
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
    req.body || {};

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
      body.payment_method
    );

  const amountMzn =
    Number(
      body.amount ??
      body.amount_mzn
    );

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

  const usdtAmount =
    calculateUsdt(
      amountMzn
    );

  const orderId =
    createOrderId();

  /*
   * Cria primeiro a ordem no banco.
   */
  const created =
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

  if (!created.length) {
    return res.status(500).json({
      success: false,
      message:
        "Não foi possível criar a ordem."
    });
  }

  const order =
    created[0];

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
      normalizeText(
        pagar?.payment_id ||
        pagar?.paymentId ||
        pagar?.id ||
        pagar?.payment?.id ||
        pagar?.data?.payment_id ||
        pagar?.data?.payment?.id
      );

    await sql`
      UPDATE orders
      SET
        pagar_payment_id =
          ${paymentId || null},
        status = 'PROCESSING',
        updated_at = NOW()
      WHERE order_id =
        ${order.order_id}
    `;

    return res.status(201).json({
      success: true,

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
          paymentId || null,

        /*
         * Mantemos a resposta completa do Pagar
         * para o frontend conseguir usar a forma
         * de pagamento retornada pela API.
         */
        data:
          pagar
      }
    });
  } catch (error) {
    console.error(
      "PAGAR CREATE PAYMENT ERROR:",
      error
    );

    await sql`
      UPDATE orders
      SET
        status = 'FAILED',
        updated_at = NOW()
      WHERE order_id =
        ${order.order_id}
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
        error?.message ||
        "Erro desconhecido."
    });
  }
}

/* =========================================================
   HANDLER
   ========================================================= */

export default async function handler(
  req,
  res
) {
  /*
   * WEBHOOK
   */
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
      )
    )
  ) {
    const databaseUrl =
      getDatabaseUrl();

    if (!databaseUrl) {
      return res.status(500).json({
        success: false,
        message:
          "Banco de dados não configurado."
      });
    }

    const rawBody =
      await readRawBody(
        req
      );

    try {
      const sql =
        neon(databaseUrl);

      return await handleWebhook(
        req,
        res,
        sql,
        rawBody
      );
    } catch (error) {
      console.error(
        "PAGAR WEBHOOK ERROR:",
        error
      );

      return res.status(500).json({
        success: false,
        message:
          "Erro ao processar webhook.",
        detail:
          error?.message ||
          "Erro desconhecido."
      });
    }
  }

  /*
   * CONSULTA MANUAL DO PAGAMENTO
   */
  if (
    req.method === "GET" &&
    req.query?.order_id
  ) {
    const databaseUrl =
      getDatabaseUrl();

    if (!databaseUrl) {
      return res.status(500).json({
        success: false,
        message:
          "Banco de dados não configurado."
      });
    }

    try {
      const sql =
        neon(databaseUrl);

      return await handleStatusCheck(
        req,
        res,
        sql
      );
    } catch (error) {
      console.error(
        "PAGAR STATUS ERROR:",
        error
      );

      return res.status(500).json({
        success: false,
        message:
          "Erro ao consultar pagamento.",
        detail:
          error?.message ||
          "Erro desconhecido."
      });
    }
  }

  /*
   * CRIAR COMPRA
   */
  if (req.method === "POST") {
    const databaseUrl =
      getDatabaseUrl();

    if (!databaseUrl) {
      return res.status(500).json({
        success: false,
        message:
          "Banco de dados não configurado."
      });
    }

    try {
      const sql =
        neon(databaseUrl);

      return await createPurchase(
        req,
        res,
        sql
      );
    } catch (error) {
      console.error(
        "CREATE PURCHASE ERROR:",
        error
      );

      return res.status(500).json({
        success: false,
        message:
          "Erro interno ao criar compra.",
        detail:
          error?.message ||
          "Erro desconhecido."
      });
    }
  }

  return res.status(405).json({
    success: false,
    message:
      "Método não permitido."
  });
}
