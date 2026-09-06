import { neon } from "@neondatabase/serverless";
import {
  createHash,
  createHmac,
  randomBytes,
  timingSafeEqual
} from "node:crypto";

export const config = {
  api: {
    bodyParser: false
  }
};

const COOKIE_NAME = "usdtmz_admin_session";

const RATE_MZN_PER_USDT = 64;
const MIN_MZN = 64;
const MAX_MZN = 40000;

const PAGAR_METHODS = new Set(["MPESA", "EMOLA"]);

function json(res, status, body) {
  res.status(status).json(body);
}

function safeCompare(a, b) {
  const A = Buffer.from(String(a));
  const B = Buffer.from(String(b));

  if (A.length !== B.length) {
    return false;
  }

  return timingSafeEqual(A, B);
}

function getCookie(req, name) {
  const cookies = req.headers.cookie || "";

  const cookie = cookies
    .split(";")
    .map((item) => item.trim())
    .find((item) => item.startsWith(`${name}=`));

  if (!cookie) {
    return null;
  }

  return cookie.substring(name.length + 1);
}

function verifyAdminSession(req) {
  const token = getCookie(req, COOKIE_NAME);
  const secret = process.env.ADMIN_SESSION_SECRET;

  if (!token || !secret) {
    return null;
  }

  const parts = token.split(".");

  if (parts.length !== 2) {
    return null;
  }

  const [data, signature] = parts;

  const expected = createHmac("sha256", secret)
    .update(data)
    .digest("base64url");

  if (!safeCompare(signature, expected)) {
    return null;
  }

  try {
    const payload = JSON.parse(
      Buffer.from(data, "base64url").toString("utf8")
    );

    if (!payload.exp || Date.now() > Number(payload.exp)) {
      return null;
    }

    if (payload.id !== "admin") {
      return null;
    }

    return payload;
  } catch {
    return null;
  }
}

async function readRawBody(req) {
  const chunks = [];

  for await (const chunk of req) {
    chunks.push(
      Buffer.isBuffer(chunk)
        ? chunk
        : Buffer.from(chunk)
    );
  }

  return Buffer.concat(chunks).toString("utf8");
}

function parseJson(rawBody) {
  if (!rawBody) {
    return {};
  }

  try {
    return JSON.parse(rawBody);
  } catch {
    return null;
  }
}

function normalizePhone(value) {
  return String(value || "")
    .replace(/\s+/g, "")
    .replace(/^\+258/, "")
    .replace(/^258/, "");
}

function isValidMozambiquePhone(phone) {
  return /^(84|85|86|87)\d{7}$/.test(phone);
}

function normalizeMethod(value) {
  return String(value || "")
    .trim()
    .toUpperCase();
}

function calculateUsdt(amountMzn) {
  return amountMzn / RATE_MZN_PER_USDT;
}

function generateOrderId() {
  const timestamp = Date.now().toString(36).toUpperCase();

  const random = randomBytes(5)
    .toString("hex")
    .toUpperCase();

  return `USDTMZ-${timestamp}-${random}`;
}

function getPagarConfig() {
  const baseUrl =
    process.env.PAGAR_API_BASE_URL ||
    "https://api.pagar.co.mz/api/v1";

  const apiKey = process.env.PAGAR_API_KEY;
  const signingSecret = process.env.PAGAR_SIGNING_SECRET;
  const webhookSecret = process.env.PAGAR_WEBHOOK_SECRET;

  if (!apiKey || !signingSecret || !webhookSecret) {
    throw new Error(
      "Configuração Pagar incompleta."
    );
  }

  return {
    baseUrl: baseUrl.replace(/\/+$/, ""),
    apiKey,
    signingSecret,
    webhookSecret
  };
}

async function parsePagarResponse(response) {
  const text = await response.text();

  let data = {};

  try {
    data = text ? JSON.parse(text) : {};
  } catch {
    data = {
      message: text || "Resposta inválida da Pagar API."
    };
  }

  if (!response.ok) {
    const error = new Error(
      data.message ||
      "Pedido rejeitado pela Pagar API."
    );

    error.status = response.status;
    error.code = data.error;
    error.requestId = data.requestId;

    throw error;
  }

  return data;
}

async function pagarGet(path) {
  const {
    baseUrl,
    apiKey
  } = getPagarConfig();

  const response = await fetch(
    `${baseUrl}${path}`,
    {
      method: "GET",
      headers: {
        Authorization: `Bearer ${apiKey}`,
        Accept: "application/json"
      }
    }
  );

  return parsePagarResponse(response);
}

async function pagarPost(
  path,
  body,
  idempotencyKey
) {
  const {
    baseUrl,
    apiKey,
    signingSecret
  } = getPagarConfig();

  const rawBody = JSON.stringify(body);

  const url = `${baseUrl}${path}`;

  const timestamp = Date.now().toString();

  const nonce = randomBytes(18)
    .toString("base64url");

  const bodyHash = createHash("sha256")
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

  const signature = createHmac(
    "sha256",
    signingSecret
  )
    .update(canonical)
    .digest("hex");

  const response = await fetch(
    url,
    {
      method: "POST",
      headers: {
        Authorization: `Bearer ${apiKey}`,
        "Content-Type": "application/json",
        Accept: "application/json",
        "Idempotency-Key": idempotencyKey,
        "X-Pagar-Timestamp": timestamp,
        "X-Pagar-Nonce": nonce,
        "X-Pagar-Signature": `v1=${signature}`
      },
      body: rawBody
    }
  );

  return parsePagarResponse(response);
}

function getWebhookHeader(req, name) {
  const value = req.headers[name.toLowerCase()];

  if (Array.isArray(value)) {
    return value[0];
  }

  return value || "";
}

function parseWebhookSignature(value) {
  const result = {};

  for (const part of String(value || "").split(",")) {
    const index = part.indexOf("=");

    if (index === -1) {
      continue;
    }

    const key = part
      .slice(0, index)
      .trim();

    const val = part
      .slice(index + 1)
      .trim();

    if (key) {
      result[key] = val;
    }
  }

  return result;
}

function verifyPagarWebhook(
  req,
  rawBody
) {
  const {
    webhookSecret
  } = getPagarConfig();

  const eventId = getWebhookHeader(
    req,
    "pagar-event-id"
  );

  const signatureHeader =
    getWebhookHeader(
      req,
      "pagar-signature"
    );

  if (!eventId) {
    return {
      valid: false,
      reason: "Pagar-Event-Id ausente."
    };
  }

  const parts =
    parseWebhookSignature(
      signatureHeader
    );

  const timestamp = parts.t;
  const received = parts.v1;

  if (
    !/^\d+$/.test(
      String(timestamp || "")
    )
  ) {
    return {
      valid: false,
      reason: "Timestamp do webhook inválido."
    };
  }

  if (
    !/^[a-f0-9]{64}$/.test(
      String(received || "")
    )
  ) {
    return {
      valid: false,
      reason: "Assinatura do webhook inválida."
    };
  }

  const timestampSeconds =
    Number(timestamp);

  if (
    !Number.isFinite(timestampSeconds)
  ) {
    return {
      valid: false,
      reason: "Timestamp inválido."
    };
  }

  const age =
    Math.abs(
      Date.now() / 1000 -
      timestampSeconds
    );

  if (age > 300) {
    return {
      valid: false,
      reason: "Webhook expirado."
    };
  }

  const expected =
    createHmac(
      "sha256",
      webhookSecret
    )
      .update(
        `${timestamp}.${rawBody}`
      )
      .digest("hex");

  if (!safeCompare(received, expected)) {
    return {
      valid: false,
      reason: "Assinatura do webhook inválida."
    };
  }

  return {
    valid: true,
    eventId
  };
}

function extractPaymentFromEvent(event) {
  if (
    event &&
    event.payment &&
    typeof event.payment === "object"
  ) {
    return event.payment;
  }

  if (
    event &&
    event.data &&
    event.data.payment &&
    typeof event.data.payment === "object"
  ) {
    return event.data.payment;
  }

  if (
    event &&
    event.data &&
    typeof event.data === "object" &&
    (
      event.data.id ||
      event.data.reference ||
      event.data.paymentId
    )
  ) {
    return event.data;
  }

  return null;
}

function extractPaymentId(payment) {
  if (!payment) {
    return null;
  }

  return (
    payment.id ||
    payment.paymentId ||
    payment.payment_id ||
    null
  );
}

function extractReference(payment) {
  if (!payment) {
    return null;
  }

  return (
    payment.reference ||
    payment.orderReference ||
    null
  );
}

function getEventType(event) {
  return String(
    event?.type ||
    event?.event ||
    event?.name ||
    ""
  )
    .trim()
    .toLowerCase();
}

async function handlePagarWebhook(
  req,
  res,
  rawBody
) {
  let verification;

  try {
    verification =
      verifyPagarWebhook(
        req,
        rawBody
      );
  } catch (error) {
    console.error(
      "Erro ao validar webhook Pagar:",
      error
    );

    return json(res, 500, {
      success: false,
      message: "Erro de configuração do webhook."
    });
  }

  if (!verification.valid) {
    return json(res, 401, {
      success: false,
      message: verification.reason
    });
  }

  const eventId =
    verification.eventId;

  let event;

  try {
    event = JSON.parse(rawBody);
  } catch {
    return json(res, 400, {
      success: false,
      message: "JSON do webhook inválido."
    });
  }

  const eventType =
    getEventType(event);

  const payment =
    extractPaymentFromEvent(event);

  const paymentId =
    extractPaymentId(payment);

  const reference =
    extractReference(payment);

  const sql = neon(
    process.env.URL_DO_BANCO_DE_DADOS ||
    process.env.POSTGRES_URL ||
    process.env.DATABASE_URL ||
    process.env.POSTGRES_URL_NON_POOLING ||
    process.env.DATABASE_URL_UNPOOLED ||
    ""
  );

  if (!paymentId && !reference) {
    await sql`
      INSERT INTO pagar_webhook_events (
        event_id,
        event_type,
        payment_id,
        reference,
        payload,
        processed_at,
        created_at
      )
      VALUES (
        ${eventId},
        ${eventType || null},
        ${null},
        ${null},
        ${JSON.stringify(event)}::jsonb,
        NOW(),
        NOW()
      )
      ON CONFLICT (event_id) DO NOTHING
    `;

    return json(res, 200, {
      success: true,
      received: true
    });
  }

  let newStatus = null;

  if (
    eventType === "payment.succeeded"
  ) {
    newStatus = "PAID";
  }

  if (
    eventType === "payment.failed"
  ) {
    newStatus = "FAILED";
  }

  /*
   * Uma única instrução SQL é atómica:
   * primeiro grava o event_id único e,
   * no mesmo comando, atualiza o pedido.
   *
   * Se o webhook for repetido, ON CONFLICT
   * não insere novamente e nenhuma atualização
   * duplicada é aplicada.
   */
  const result = await sql`
    WITH inserted_event AS (
      INSERT INTO pagar_webhook_events (
        event_id,
        event_type,
        payment_id,
        reference,
        payload,
        processed_at,
        created_at
      )
      VALUES (
        ${eventId},
        ${eventType || null},
        ${paymentId},
        ${reference},
        ${JSON.stringify(event)}::jsonb,
        NOW(),
        NOW()
      )
      ON CONFLICT (event_id) DO NOTHING
      RETURNING event_id
    ),
    updated_order AS (
      UPDATE orders
      SET
        status = ${newStatus || "PROCESSING"},
        pagar_payment_id =
          COALESCE(
            ${paymentId},
            pagar_payment_id
          ),
        pagar_event_id =
          CASE
            WHEN ${newStatus === "PAID" ? eventId : null}
              IS NOT NULL
            THEN ${eventId}
            ELSE pagar_event_id
          END,
        updated_at = NOW()
      WHERE
        EXISTS (
          SELECT 1
          FROM inserted_event
        )
        AND (
          (
            ${reference} IS NOT NULL
            AND order_id = ${reference}
          )
          OR
          (
            ${paymentId} IS NOT NULL
            AND pagar_payment_id = ${paymentId}
          )
        )
        AND (
          ${newStatus === "PAID" ? "PAID" : null} IS NULL
          OR status <> 'PAID'
        )
      RETURNING
        order_id,
        status,
        amount,
        usdt_amount,
        rate,
        pagar_payment_id,
        pagar_event_id
    )
    SELECT
      EXISTS (
        SELECT 1
        FROM inserted_event
      ) AS inserted,
      COALESCE(
        (
          SELECT row_to_json(updated_order)
          FROM updated_order
          LIMIT 1
        ),
        NULL
      ) AS updated
  `;

  return json(res, 200, {
    success: true,
    received: true,
    event_id: eventId,
    duplicate: result[0]?.inserted !== true,
    order: result[0]?.updated || null
  });
}

async function handleCheckStatus(
  req,
  res,
  body
) {
  const orderId =
    String(body.order_id || "")
      .trim();

  if (!orderId) {
    return json(res, 400, {
      success: false,
      message: "order_id é obrigatório."
    });
  }

  const databaseUrl =
    process.env.URL_DO_BANCO_DE_DADOS ||
    process.env.POSTGRES_URL ||
    process.env.DATABASE_URL ||
    process.env.POSTGRES_URL_NON_POOLING ||
    process.env.DATABASE_URL_UNPOOLED;

  if (!databaseUrl) {
    return json(res, 500, {
      success: false,
      message: "Banco de dados não configurado."
    });
  }

  const sql = neon(databaseUrl);

  const rows = await sql`
    SELECT
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
      pagar_event_id,
      blockchain_tx_hash
    FROM orders
    WHERE order_id = ${orderId}
    LIMIT 1
  `;

  if (rows.length === 0) {
    return json(res, 404, {
      success: false,
      message: "Pedido não encontrado."
    });
  }

  const order = rows[0];

  if (
    order.pagar_payment_id
  ) {
    try {
      const response =
        await pagarGet(
          `/payments/${encodeURIComponent(
            order.pagar_payment_id
          )}`
        );

      const payment =
        response?.payment ||
        response;

      const pagarStatus =
        String(
          payment?.status || ""
        )
          .trim()
          .toUpperCase();

      if (
        pagarStatus &&
        [
          "PENDING",
          "PROCESSING",
          "PAID",
          "CANCELLED",
          "FAILED",
          "RECONCILIATION_REQUIRED"
        ].includes(pagarStatus)
      ) {
        /*
         * A consulta autenticada pode confirmar PAID,
         * conforme o guia oficial.
         *
         * Não substituímos um PAID por um estado
         * não-terminal posterior.
         */
        if (
          pagarStatus === "PAID" &&
          String(order.status)
            .toUpperCase() !== "PAID"
        ) {
          const updated =
            await sql`
              UPDATE orders
              SET
                status = 'PAID',
                updated_at = NOW()
              WHERE order_id = ${orderId}
                AND status <> 'PAID'
              RETURNING
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
                pagar_event_id,
                blockchain_tx_hash
            `;

          if (updated.length > 0) {
            order.status =
              updated[0].status;
            order.updated_at =
              updated[0].updated_at;
          }
        }

        if (
          [
            "CANCELLED",
            "FAILED",
            "RECONCILIATION_REQUIRED"
          ].includes(pagarStatus) &&
          String(order.status)
            .toUpperCase() !== "PAID"
        ) {
          const updated =
            await sql`
              UPDATE orders
              SET
                status = ${pagarStatus},
                updated_at = NOW()
              WHERE order_id = ${orderId}
                AND status <> 'PAID'
              RETURNING status
            `;

          if (updated.length > 0) {
            order.status =
              updated[0].status;
          }
        }
      }
    } catch (error) {
      console.error(
        "Erro ao consultar pagamento Pagar:",
        error
      );

      /*
       * Não transformamos um erro de consulta
       * em FAILED. O estado financeiro continua
       * sendo o estado conhecido da nossa base.
       */
    }
  }

  return json(res, 200, {
    success: true,
    order: {
      order_id: order.order_id,
      amount_mzn: Number(order.amount),
      usdt_amount: Number(order.usdt_amount),
      rate: Number(order.rate),
      status: order.status,
      pagar_payment_id:
        order.pagar_payment_id,
      blockchain_tx_hash:
        order.blockchain_tx_hash,
      created_at: order.created_at,
      updated_at: order.updated_at
    }
  });
}

async function handleCreatePurchase(
  req,
  res,
  body
) {
  const adminSession =
    verifyAdminSession(req);

  if (!adminSession) {
    return json(res, 401, {
      success: false,
      authenticated: false,
      message: "Sessão Admin inválida ou expirada."
    });
  }

  const amountRaw =
    body.amount_mzn;

  const method =
    normalizeMethod(
      body.payment_method ||
      body.method
    );

  const payerPhone =
    normalizePhone(
      body.payerPhone ||
      body.payer_phone
    );

  const amount =
    Number(amountRaw);

  if (
    !Number.isFinite(amount) ||
    !Number.isInteger(amount)
  ) {
    return json(res, 400, {
      success: false,
      message: "O valor deve ser um número inteiro em MZN."
    });
  }

  if (
    amount < MIN_MZN ||
    amount > MAX_MZN
  ) {
    return json(res, 400, {
      success: false,
      message:
        `O valor deve estar entre ${MIN_MZN} MZN e ${MAX_MZN} MZN.`
    });
  }

  if (!PAGAR_METHODS.has(method)) {
    return json(res, 400, {
      success: false,
      message: "Método de pagamento inválido. Use MPESA ou EMOLA."
    });
  }

  if (!isValidMozambiquePhone(payerPhone)) {
    return json(res, 400, {
      success: false,
      message:
        "Número M-Pesa/e-Mola inválido. Use um número moçambicano válido."
    });
  }

  const usdtAmount =
    calculateUsdt(amount);

  if (
    !Number.isFinite(usdtAmount) ||
    usdtAmount <= 0
  ) {
    return json(res, 400, {
      success: false,
      message: "Não foi possível calcular o valor USDT."
    });
  }

  const databaseUrl =
    process.env.URL_DO_BANCO_DE_DADOS ||
    process.env.POSTGRES_URL ||
    process.env.DATABASE_URL ||
    process.env.POSTGRES_URL_NON_POOLING ||
    process.env.DATABASE_URL_UNPOOLED;

  if (!databaseUrl) {
    return json(res, 500, {
      success: false,
      message: "Banco de dados não configurado."
    });
  }

  const sql = neon(databaseUrl);

  const orderId =
    generateOrderId();

  /*
   * Título, descrição, valor e quantidade
   * são derivados pelo backend.
   *
   * O frontend não controla o preço.
   */
  const title =
    `Compra de ${usdtAmount} USDT - USDTMZ`;

  const description =
    `${amount} MZN para compra de ${usdtAmount} USDT ` +
    `à taxa fixa de ${RATE_MZN_PER_USDT} MZN por USDT.`;

  try {
    const inserted =
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
          'USDTMZ ADMIN',
          ${payerPhone},
          'BUY_USDT_ADMIN',
          ${method},
          ${amount},
          ${usdtAmount},
          ${RATE_MZN_PER_USDT},
          'PENDING',
          NOW(),
          NOW()
        )
        RETURNING
          id,
          order_id,
          amount,
          usdt_amount,
          rate,
          status
      `;

    if (inserted.length === 0) {
      return json(res, 500, {
        success: false,
        message: "Não foi possível criar o pedido."
      });
    }

    const order =
      inserted[0];

    const pagarBody = {
      reference: order.order_id,
      title,
      description,
      amountMzn: amount,
      method,
      payerPhone
    };

    const idempotencyKey =
      `payment:${order.id}`;

    let pagarResponse;

    try {
      pagarResponse =
        await pagarPost(
          "/payments",
          pagarBody,
          idempotencyKey
        );
    } catch (error) {
      /*
       * Não apagamos o pedido.
       * O estado permanece PENDING para
       * reconciliação/repetição controlada.
       */
      console.error(
        "Erro ao criar pagamento Pagar:",
        {
          message: error.message,
          status: error.status,
          code: error.code,
          requestId: error.requestId
        }
      );

      return json(res, 502, {
        success: false,
        message:
          "A Pagar não confirmou a criação do pagamento. O pedido foi preservado para reconciliação.",
        order_id: order.order_id,
        request_id:
          error.requestId || null
      });
    }

    const payment =
      pagarResponse?.payment ||
      null;

    if (!payment?.id) {
      return json(res, 502, {
        success: false,
        message:
          "A Pagar respondeu sem um payment.id. O pedido foi preservado para reconciliação.",
        order_id: order.order_id
      });
    }

    const pagarStatus =
      String(
        payment.status ||
        "PENDING"
      )
        .trim()
        .toUpperCase();

    const validStatuses = [
      "PENDING",
      "PROCESSING",
      "PAID",
      "CANCELLED",
      "FAILED",
      "RECONCILIATION_REQUIRED"
    ];

    const internalStatus =
      validStatuses.includes(
        pagarStatus
      )
        ? pagarStatus
        : "PROCESSING";

    const saved =
      await sql`
        UPDATE orders
        SET
          pagar_payment_id = ${payment.id},
          status = ${internalStatus},
          updated_at = NOW()
        WHERE order_id = ${order.order_id}
        RETURNING
          order_id,
          amount,
          usdt_amount,
          rate,
          status,
          pagar_payment_id,
          created_at,
          updated_at
      `;

    return json(res, 202, {
      success: true,
      message:
        "Pagamento enviado para processamento.",
      order: saved[0] || {
        order_id: order.order_id,
        amount: amount,
        usdt_amount: usdtAmount,
        rate: RATE_MZN_PER_USDT,
        status: internalStatus,
        pagar_payment_id: payment.id
      },
      payment: {
        id: payment.id,
        status: pagarStatus,
        reference:
          payment.reference ||
          order.order_id,
        amountMzn:
          payment.amountMzn ??
          amount,
        currency:
          payment.currency ||
          "MZN",
        method:
          payment.method ||
          method,
        payerPhone:
          payment.payerPhone ||
          null,
        paidAt:
          payment.paidAt ||
          null
      }
    });
  } catch (error) {
    console.error(
      "Erro ao criar compra USDTMZ:",
      error
    );

    return json(res, 500, {
      success: false,
      message:
        "Erro interno ao criar a compra."
    });
  }
}

export default async function handler(
  req,
  res
) {
  if (req.method !== "POST") {
    return json(res, 405, {
      success: false,
      message: "Método não permitido."
    });
  }

  const rawBody =
    await readRawBody(req);

  /*
   * Webhook Pagar:
   * possui Pagar-Event-Id + Pagar-Signature.
   *
   * Ele não usa a sessão Admin.
   */
  const isWebhook =
    Boolean(
      getWebhookHeader(
        req,
        "pagar-event-id"
      )
    ) ||
    Boolean(
      getWebhookHeader(
        req,
        "pagar-signature"
      )
    );

  if (isWebhook) {
    try {
      return await handlePagarWebhook(
        req,
        res,
        rawBody
      );
    } catch (error) {
      console.error(
        "Erro no webhook Pagar:",
        error
      );

      return json(res, 500, {
        success: false,
        message:
          "Erro interno no processamento do webhook."
      });
    }
  }

  const body =
    parseJson(rawBody);

  if (!body) {
    return json(res, 400, {
      success: false,
      message: "JSON inválido."
    });
  }

  const adminSession =
    verifyAdminSession(req);

  if (!adminSession) {
    return json(res, 401, {
      success: false,
      authenticated: false,
      message: "Sessão Admin inválida ou expirada."
    });
  }

  if (
    body.check_status === true
  ) {
    return handleCheckStatus(
      req,
      res,
      body
    );
  }

  return handleCreatePurchase(
    req,
    res,
    body
  );
}
