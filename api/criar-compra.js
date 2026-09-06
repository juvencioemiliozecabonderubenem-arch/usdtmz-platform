import { neon } from "@neondatabase/serverless";
import {
  createHash,
  createHmac,
  randomBytes,
  timingSafeEqual
} from "node:crypto";

import {
  processAdminPurchaseToBinanceInternal
} from "./admin-withdrawal-process.js";

export const config = {
  api: {
    bodyParser: false
  }
};

const COOKIE_NAME = "usdtmz_admin_session";

const RATE_MZN_PER_USDT = 64;
const MIN_MZN = 64;
const MAX_MZN = 40000;

const PAGAR_METHODS =
  new Set(["MPESA", "EMOLA"]);

const PAGAR_STATUSES =
  new Set([
    "PENDING",
    "PROCESSING",
    "PAID",
    "CANCELLED",
    "FAILED",
    "RECONCILIATION_REQUIRED"
  ]);

function json(res, status, body) {
  return res.status(status).json(body);
}

/*
 * =========================================================
 * SEGURANÇA
 * =========================================================
 */

function safeCompare(a, b) {
  const A = Buffer.from(String(a));
  const B = Buffer.from(String(b));

  if (A.length !== B.length) {
    return false;
  }

  return timingSafeEqual(A, B);
}

function getCookie(req, name) {
  const cookies =
    req.headers.cookie || "";

  const cookie = cookies
    .split(";")
    .map((item) => item.trim())
    .find((item) =>
      item.startsWith(`${name}=`)
    );

  if (!cookie) {
    return null;
  }

  return cookie.substring(
    name.length + 1
  );
}

function verifyAdminSession(req) {
  const token =
    getCookie(
      req,
      COOKIE_NAME
    );

  const secret =
    process.env.ADMIN_SESSION_SECRET;

  if (!token || !secret) {
    return null;
  }

  const parts =
    token.split(".");

  if (parts.length !== 2) {
    return null;
  }

  const [data, signature] =
    parts;

  const expected =
    createHmac(
      "sha256",
      secret
    )
      .update(data)
      .digest("base64url");

  if (
    !safeCompare(
      signature,
      expected
    )
  ) {
    return null;
  }

  try {
    const payload =
      JSON.parse(
        Buffer.from(
          data,
          "base64url"
        ).toString("utf8")
      );

    if (
      !payload.exp ||
      Date.now() >
        Number(payload.exp)
    ) {
      return null;
    }

    if (
      payload.id !== "admin"
    ) {
      return null;
    }

    return payload;
  } catch {
    return null;
  }
}

/*
 * =========================================================
 * BODY
 * =========================================================
 */

async function readRawBody(req) {
  const chunks = [];

  for await (
    const chunk of req
  ) {
    chunks.push(
      Buffer.isBuffer(chunk)
        ? chunk
        : Buffer.from(chunk)
    );
  }

  return Buffer.concat(
    chunks
  ).toString("utf8");
}

function parseJson(rawBody) {
  if (!rawBody) {
    return {};
  }

  try {
    return JSON.parse(
      rawBody
    );
  } catch {
    return null;
  }
}

/*
 * =========================================================
 * DADOS DA COMPRA
 * =========================================================
 */

function normalizePhone(value) {
  return String(value || "")
    .replace(/\s+/g, "")
    .replace(/^\+258/, "")
    .replace(/^258/, "");
}

function isValidMozambiquePhone(
  phone
) {
  return /^(84|85|86|87)\d{7}$/.test(
    phone
  );
}

function normalizeMethod(value) {
  return String(value || "")
    .trim()
    .toUpperCase();
}

function calculateUsdt(
  amountMzn
) {
  return (
    amountMzn /
    RATE_MZN_PER_USDT
  );
}

function generateOrderId() {
  const timestamp =
    Date.now()
      .toString(36)
      .toUpperCase();

  const random =
    randomBytes(5)
      .toString("hex")
      .toUpperCase();

  return (
    `USDTMZ-${timestamp}-${random}`
  );
}

function getDatabaseUrl() {
  return (
    process.env.URL_DO_BANCO_DE_DADOS ||
    process.env.POSTGRES_URL ||
    process.env.DATABASE_URL ||
    process.env.POSTGRES_URL_NON_POOLING ||
    process.env.DATABASE_URL_UNPOOLED
  );
}

/*
 * =========================================================
 * PAGAR CONFIG
 * =========================================================
 */

function getPagarConfig() {
  const baseUrl =
    process.env.PAGAR_API_BASE_URL ||
    "https://api.pagar.co.mz/api/v1";

  const apiKey =
    process.env.PAGAR_API_KEY;

  const signingSecret =
    process.env.PAGAR_SIGNING_SECRET;

  const webhookSecret =
    process.env.PAGAR_WEBHOOK_SECRET;

  if (
    !apiKey ||
    !signingSecret ||
    !webhookSecret
  ) {
    throw new Error(
      "Configuração Pagar incompleta."
    );
  }

  return {
    baseUrl:
      baseUrl.replace(
        /\/+$/,
        ""
      ),
    apiKey,
    signingSecret,
    webhookSecret
  };
}

/*
 * =========================================================
 * PAGAR RESPONSE
 * =========================================================
 */

async function parsePagarResponse(
  response
) {
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
      message:
        text ||
        "Resposta inválida da Pagar API."
    };
  }

  if (!response.ok) {
    const error =
      new Error(
        data.message ||
        "Pedido rejeitado pela Pagar API."
      );

    error.status =
      response.status;

    error.code =
      data.error;

    error.requestId =
      data.requestId;

    throw error;
  }

  return data;
}

/*
 * =========================================================
 * PAGAR GET
 * =========================================================
 */

async function pagarGet(path) {
  const {
    baseUrl,
    apiKey
  } = getPagarConfig();

  const response =
    await fetch(
      `${baseUrl}${path}`,
      {
        method: "GET",
        headers: {
          Authorization:
            `Bearer ${apiKey}`,
          Accept:
            "application/json"
        }
      }
    );

  return parsePagarResponse(
    response
  );
}

/*
 * =========================================================
 * PAGAR POST ASSINADO
 * =========================================================
 */

async function pagarPost(
  path,
  body,
  idempotencyKey
) {
  const {
    baseUrl,
    apiKey,
    signingSecret
  } =
    getPagarConfig();

  const rawBody =
    JSON.stringify(body);

  const url =
    `${baseUrl}${path}`;

  const timestamp =
    Date.now().toString();

  const nonce =
    randomBytes(18)
      .toString("base64url");

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
    await fetch(
      url,
      {
        method: "POST",
        headers: {
          Authorization:
            `Bearer ${apiKey}`,

          "Content-Type":
            "application/json",

          Accept:
            "application/json",

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
      }
    );

  return parsePagarResponse(
    response
  );
}

/*
 * =========================================================
 * WEBHOOK PAGAR
 * =========================================================
 */

function getWebhookHeader(
  req,
  name
) {
  const value =
    req.headers[
      name.toLowerCase()
    ];

  if (
    Array.isArray(value)
  ) {
    return value[0];
  }

  return value || "";
}

function parseWebhookSignature(
  value
) {
  const result = {};

  for (
    const part of String(
      value || ""
    ).split(",")
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

    const val =
      part
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
  } =
    getPagarConfig();

  const eventId =
    getWebhookHeader(
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
      reason:
        "Pagar-Event-Id ausente."
    };
  }

  const parts =
    parseWebhookSignature(
      signatureHeader
    );

  const timestamp =
    parts.t;

  const received =
    parts.v1;

  if (
    !/^\d+$/.test(
      String(timestamp || "")
    )
  ) {
    return {
      valid: false,
      reason:
        "Timestamp do webhook inválido."
    };
  }

  if (
    !/^[a-f0-9]{64}$/.test(
      String(received || "")
    )
  ) {
    return {
      valid: false,
      reason:
        "Assinatura do webhook inválida."
    };
  }

  const timestampSeconds =
    Number(timestamp);

  if (
    !Number.isFinite(
      timestampSeconds
    )
  ) {
    return {
      valid: false,
      reason:
        "Timestamp inválido."
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
      reason:
        "Webhook expirado."
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

  if (
    !safeCompare(
      received,
      expected
    )
  ) {
    return {
      valid: false,
      reason:
        "Assinatura do webhook inválida."
    };
  }

  return {
    valid: true,
    eventId
  };
}

/*
 * =========================================================
 * EXTRAÇÃO DO EVENTO PAGAR
 * =========================================================
 */

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

function extractPaymentFromEvent(
  event
) {
  if (
    event &&
    event.payment &&
    typeof event.payment ===
      "object"
  ) {
    return event.payment;
  }

  if (
    event &&
    event.data &&
    event.data.payment &&
    typeof event.data.payment ===
      "object"
  ) {
    return event.data.payment;
  }

  if (
    event &&
    event.data &&
    typeof event.data ===
      "object" &&
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

function extractPaymentId(
  payment
) {
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

function extractReference(
  payment
) {
  if (!payment) {
    return null;
  }

  return (
    payment.reference ||
    payment.orderReference ||
    null
  );
}

/*
 * =========================================================
 * PROCESSAMENTO AUTOMÁTICO
 * =========================================================
 */

async function triggerAutomaticBinanceTransfer(
  orderId
) {
  try {
    const result =
      await processAdminPurchaseToBinanceInternal(
        orderId
      );

    console.log(
      "AUTO BINANCE TRANSFER RESULT:",
      {
        order_id:
          orderId,
        status:
          result?.body?.status ||
          result?.body?.message ||
          null
      }
    );

    return result;
  } catch (error) {
    console.error(
      "AUTO BINANCE TRANSFER ERROR:",
      {
        order_id:
          orderId,
        message:
          error?.message ||
          "Erro desconhecido."
      }
    );

    return null;
  }
}

/*
 * =========================================================
 * WEBHOOK
 * =========================================================
 */

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

    return json(
      res,
      500,
      {
        success: false,
        message:
          "Erro de configuração do webhook."
      }
    );
  }

  if (!verification.valid) {
    return json(
      res,
      401,
      {
        success: false,
        message:
          verification.reason
      }
    );
  }

  const eventId =
    verification.eventId;

  let event;

  try {
    event =
      JSON.parse(
        rawBody
      );
  } catch {
    return json(
      res,
      400,
      {
        success: false,
        message:
          "JSON do webhook inválido."
      }
    );
  }

  const eventType =
    getEventType(event);

  const payment =
    extractPaymentFromEvent(
      event
    );

  const paymentId =
    extractPaymentId(
      payment
    );

  const reference =
    extractReference(
      payment
    );

  const databaseUrl =
    getDatabaseUrl();

  if (!databaseUrl) {
    return json(
      res,
      500,
      {
        success: false,
        message:
          "Banco de dados não configurado."
      }
    );
  }

  const sql =
    neon(databaseUrl);

  /*
   * Eventos sem payment/reference:
   * guardar e responder 200.
   */
  if (
    !paymentId &&
    !reference
  ) {
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
      ON CONFLICT (event_id)
      DO NOTHING
    `;

    return json(
      res,
      200,
      {
        success: true,
        received: true,
        event_id:
          eventId
      }
    );
  }

  let newStatus = null;

  if (
    eventType ===
    "payment.succeeded"
  ) {
    newStatus = "PAID";
  } else if (
    eventType ===
    "payment.failed"
  ) {
    newStatus = "FAILED";
  }

  /*
   * =======================================================
   * REGISTRA EVENTO + ATUALIZA PEDIDO
   * =======================================================
   *
   * ON CONFLICT garante idempotência do webhook.
   */
  const result =
    await sql`
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
        ON CONFLICT (event_id)
        DO NOTHING
        RETURNING event_id
      ),

      updated_order AS (
        UPDATE orders
        SET
          status =
            CASE
              WHEN ${newStatus || null}
                IS NOT NULL
              THEN ${newStatus}
              ELSE status
            END,

          pagar_payment_id =
            COALESCE(
              ${paymentId},
              pagar_payment_id
            ),

          pagar_event_id =
            CASE
              WHEN ${newStatus === "PAID"
                ? eventId
                : null} IS NOT NULL
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
              AND pagar_payment_id =
                ${paymentId}
            )
          )

          /*
           * PAID nunca volta para outro estado.
           */
          AND NOT (
            status = 'PAID'
            AND ${newStatus || null}
              IN (
                'FAILED',
                'PROCESSING',
                'PENDING'
              )
          )

        RETURNING
          order_id,
          status,
          amount,
          usdt_amount,
          rate,
          pagar_payment_id,
          pagar_event_id,
          blockchain_tx_hash
      )

      SELECT
        EXISTS (
          SELECT 1
          FROM inserted_event
        ) AS inserted,

        COALESCE(
          (
            SELECT row_to_json(
              updated_order
            )
            FROM updated_order
            LIMIT 1
          ),
          NULL
        ) AS updated
    `;

  const inserted =
    result[0]?.inserted === true;

  const updatedOrder =
    result[0]?.updated || null;

  /*
   * Webhook duplicado:
   * não processar novamente.
   */
  if (!inserted) {
    return json(
      res,
      200,
      {
        success: true,
        received: true,
        duplicate: true,
        event_id:
          eventId
      }
    );
  }

  /*
   * =======================================================
   * PAGAMENTO CONFIRMADO
   * =======================================================
   *
   * Somente payment.succeeded pode iniciar a entrega.
   */
  if (
    eventType ===
      "payment.succeeded" &&
    updatedOrder &&
    String(
      updatedOrder.status
    ).toUpperCase() ===
      "PAID"
  ) {
    /*
     * O processamento automático é feito
     * diretamente pela função interna.
     *
     * Não usamos HTTP nem sessão Admin.
     */
    await triggerAutomaticBinanceTransfer(
      updatedOrder.order_id
    );
  }

  return json(
    res,
    200,
    {
      success: true,
      received: true,
      duplicate: false,
      event_id:
        eventId,
      order:
        updatedOrder
    }
  );
}

/*
 * =========================================================
 * CHECK STATUS
 * =========================================================
 */

async function handleCheckStatus(
  req,
  res,
  body
) {
  const orderId =
    String(
      body.order_id || ""
    ).trim();

  if (!orderId) {
    return json(
      res,
      400,
      {
        success: false,
        message:
          "order_id é obrigatório."
      }
    );
  }

  const databaseUrl =
    getDatabaseUrl();

  if (!databaseUrl) {
    return json(
      res,
      500,
      {
        success: false,
        message:
          "Banco de dados não configurado."
      }
    );
  }

  const sql =
    neon(databaseUrl);

  const rows =
    await sql`
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
    return json(
      res,
      404,
      {
        success: false,
        message:
          "Pedido não encontrado."
      }
    );
  }

  const order =
    rows[0];

  /*
   * =======================================================
   * CONSULTA AUTENTICADA NA PAGAR
   * =======================================================
   */

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
        PAGAR_STATUSES.has(
          pagarStatus
        )
      ) {
        /*
         * Somente PAID pode liberar a entrega.
         */
        if (
          pagarStatus === "PAID" &&
          String(
            order.status
          ).toUpperCase() !==
            "PAID" &&
          String(
            order.status
          ).toUpperCase() !==
            "COMPLETED"
        ) {
          const updated =
            await sql`
              UPDATE orders
              SET
                status = 'PAID',
                updated_at = NOW()
              WHERE order_id =
                ${orderId}
                AND status NOT IN (
                  'PAID',
                  'COMPLETED'
                )
              RETURNING
                order_id,
                status,
                amount,
                usdt_amount,
                rate,
                pagar_payment_id,
                pagar_event_id,
                blockchain_tx_hash
            `;

          if (
            updated.length > 0
          ) {
            order.status =
              updated[0].status;

            order.updated_at =
              new Date();

            /*
             * GET autenticado confirmou PAID.
             * Pode iniciar a entrega.
             */
            await triggerAutomaticBinanceTransfer(
              orderId
            );
          }
        } else if (
          pagarStatus === "PAID" &&
          String(
            order.status
          ).toUpperCase() ===
            "PAID" &&
          !order.blockchain_tx_hash
        ) {
          /*
           * Caso o webhook tenha falhado,
           * a consulta autenticada também consegue
           * iniciar a transferência.
           */
          await triggerAutomaticBinanceTransfer(
            orderId
          );
        }

        /*
         * Estados finais da Pagar não podem sobrescrever
         * uma ordem que já foi PAID/COMPLETED.
         */
        if (
          [
            "CANCELLED",
            "FAILED",
            "RECONCILIATION_REQUIRED"
          ].includes(
            pagarStatus
          ) &&
          ![
            "PAID",
            "COMPLETED"
          ].includes(
            String(
              order.status
            ).toUpperCase()
          )
        ) {
          const updated =
            await sql`
              UPDATE orders
              SET
                status =
                  ${pagarStatus},
                updated_at =
                  NOW()
              WHERE order_id =
                ${orderId}
                AND status NOT IN (
                  'PAID',
                  'COMPLETED'
                )
              RETURNING status
            `;

          if (
            updated.length > 0
          ) {
            order.status =
              updated[0].status;
          }
        }
      }
    } catch (error) {
      /*
       * Uma falha na consulta Pagar não transforma
       * uma compra em PAID.
       */
      console.error(
        "Erro ao consultar pagamento Pagar:",
        {
          message:
            error?.message ||
            "Erro desconhecido.",
          status:
            error?.status ||
            null,
          code:
            error?.code ||
            null,
          requestId:
            error?.requestId ||
            null
        }
      );
    }
  }

  /*
   * Recarrega estado final.
   */
  const finalRows =
    await sql`
      SELECT
        order_id,
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
      WHERE order_id =
        ${orderId}
      LIMIT 1
    `;

  const finalOrder =
    finalRows[0] || order;

  return json(
    res,
    200,
    {
      success: true,
      order: {
        order_id:
          finalOrder.order_id,

        amount_mzn:
          Number(
            finalOrder.amount
          ),

        usdt_amount:
          Number(
            finalOrder.usdt_amount
          ),

        rate:
          Number(
            finalOrder.rate
          ),

        status:
          finalOrder.status,

        pagar_payment_id:
          finalOrder.pagar_payment_id,

        pagar_event_id:
          finalOrder.pagar_event_id,

        blockchain_tx_hash:
          finalOrder.blockchain_tx_hash,

        created_at:
          finalOrder.created_at,

        updated_at:
          finalOrder.updated_at
      }
    }
  );
}

/*
 * =========================================================
 * CRIAR COMPRA
 * =========================================================
 */

async function handleCreatePurchase(
  req,
  res,
  body
) {
  const adminSession =
    verifyAdminSession(req);

  if (!adminSession) {
    return json(
      res,
      401,
      {
        success: false,
        authenticated: false,
        message:
          "Sessão Admin inválida ou expirada."
      }
    );
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

  /*
   * MZN deve ser inteiro.
   */
  if (
    !Number.isFinite(amount) ||
    !Number.isInteger(amount)
  ) {
    return json(
      res,
      400,
      {
        success: false,
        message:
          "O valor deve ser um número inteiro em MZN."
      }
    );
  }

  /*
   * Limites internos USDTMZ.
   */
  if (
    amount < MIN_MZN ||
    amount > MAX_MZN
  ) {
    return json(
      res,
      400,
      {
        success: false,
        message:
          `O valor deve estar entre ${MIN_MZN} MZN e ${MAX_MZN} MZN.`
      }
    );
  }

  /*
   * Método Pagar.
   */
  if (
    !PAGAR_METHODS.has(
      method
    )
  ) {
    return json(
      res,
      400,
      {
        success: false,
        message:
          "Método de pagamento inválido. Use MPESA ou EMOLA."
      }
    );
  }

  /*
   * Telefone.
   */
  if (
    !isValidMozambiquePhone(
      payerPhone
    )
  ) {
    return json(
      res,
      400,
      {
        success: false,
        message:
          "Número M-Pesa/e-Mola inválido. Use um número moçambicano válido."
      }
    );
  }

  /*
   * =======================================================
   * CÁLCULO INTERNO
   * =======================================================
   *
   * O navegador não decide a quantidade de USDT.
   */
  const usdtAmount =
    calculateUsdt(
      amount
    );

  if (
    !Number.isFinite(
      usdtAmount
    ) ||
    usdtAmount <= 0
  ) {
    return json(
      res,
      400,
      {
        success: false,
        message:
          "Não foi possível calcular o valor USDT."
      }
    );
  }

  const databaseUrl =
    getDatabaseUrl();

  if (!databaseUrl) {
    return json(
      res,
      500,
      {
        success: false,
        message:
          "Banco de dados não configurado."
      }
    );
  }

  const sql =
    neon(databaseUrl);

  const orderId =
    generateOrderId();

  /*
   * Título e descrição derivados
   * dos dados internos.
   */
  const title =
    `Compra de ${usdtAmount} USDT - USDTMZ`;

  const description =
    `${amount} MZN para compra de ${usdtAmount} USDT ` +
    `à taxa de ${RATE_MZN_PER_USDT} MZN por USDT.`;

  try {
    /*
     * =====================================================
     * CRIAR ORDEM INTERNA PRIMEIRO
     * =====================================================
     */

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

    if (
      inserted.length === 0
    ) {
      return json(
        res,
        500,
        {
          success: false,
          message:
            "Não foi possível criar o pedido."
        }
      );
    }

    const order =
      inserted[0];

    /*
     * =====================================================
     * PAGAR
     * =====================================================
     */

    const pagarBody = {
      reference:
        order.order_id,

      title,

      description,

      amountMzn:
        Number(
          order.amount
        ),

      method,

      payerPhone
    };

    /*
     * Idempotência oficial baseada
     * no ID interno da ordem.
     */
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
       * Não apagamos a ordem.
       *
       * A Pagar pode ter processado o pedido
       * mesmo que a resposta tenha falhado.
       */
      console.error(
        "Erro ao criar pagamento Pagar:",
        {
          message:
            error?.message ||
            "Erro desconhecido.",
          status:
            error?.status ||
            null,
          code:
            error?.code ||
            null,
          requestId:
            error?.requestId ||
            null
        }
      );

      return json(
        res,
        502,
        {
          success: false,
          message:
            "A Pagar não confirmou a criação do pagamento. O pedido foi preservado para reconciliação.",
          order_id:
            order.order_id,
          request_id:
            error?.requestId ||
            null
        }
      );
    }

    const payment =
      pagarResponse?.payment ||
      null;

    if (!payment?.id) {
      return json(
        res,
        502,
        {
          success: false,
          message:
            "A Pagar respondeu sem um payment.id. O pedido foi preservado para reconciliação.",
          order_id:
            order.order_id
        }
      );
    }

    const pagarStatus =
      String(
        payment.status ||
        "PENDING"
      )
        .trim()
        .toUpperCase();

    const internalStatus =
      PAGAR_STATUSES.has(
        pagarStatus
      )
        ? pagarStatus
        : "PROCESSING";

    /*
     * =====================================================
     * GUARDAR PAYMENT ID
     * =====================================================
     */

    const saved =
      await sql`
        UPDATE orders
        SET
          pagar_payment_id =
            ${payment.id},

          status =
            CASE
              /*
               * Mesmo que a Pagar responda PAID,
               * a entrega só é feita depois da confirmação
               * autenticada/webhook.
               */
              WHEN ${internalStatus}
                = 'PAID'
              THEN 'PAID'

              ELSE ${internalStatus}
            END,

          updated_at =
            NOW()

        WHERE order_id =
          ${order.order_id}

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

    /*
     * =====================================================
     * IMPORTANTE:
     *
     * NÃO enviamos para Binance aqui somente porque
     * o POST inicial respondeu.
     *
     * A confirmação será feita pelo webhook ou GET
     * autenticado da Pagar.
     * =====================================================
     */

    return json(
      res,
      202,
      {
        success: true,

        message:
          "Pagamento enviado para processamento. O USDT será enviado automaticamente somente após confirmação PAID.",

        order:
          saved[0] || {
            order_id:
              order.order_id,

            amount:
              amount,

            usdt_amount:
              usdtAmount,

            rate:
              RATE_MZN_PER_USDT,

            status:
              internalStatus,

            pagar_payment_id:
              payment.id
          },

        payment: {
          id:
            payment.id,

          status:
            pagarStatus,

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
            payerPhone,

          paidAt:
            payment.paidAt ||
            null
        }
      }
    );
  } catch (error) {
    console.error(
      "Erro ao criar compra USDTMZ:",
      error
    );

    return json(
      res,
      500,
      {
        success: false,
        message:
          "Erro interno ao criar a compra."
      }
    );
  }
}

/*
 * =========================================================
 * HANDLER
 * =========================================================
 */

export default async function handler(
  req,
  res
) {
  if (
    req.method !== "POST"
  ) {
    return json(
      res,
      405,
      {
        success: false,
        message:
          "Método não permitido."
      }
    );
  }

  const rawBody =
    await readRawBody(req);

  /*
   * Webhook Pagar é identificado
   * pelos headers oficiais.
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

      return json(
        res,
        500,
        {
          success: false,
          message:
            "Erro interno no processamento do webhook."
        }
      );
    }
  }

  const body =
    parseJson(rawBody);

  if (!body) {
    return json(
      res,
      400,
      {
        success: false,
        message:
          "JSON inválido."
      }
    );
  }

  /*
   * Toda chamada que não é webhook
   * exige sessão Admin.
   */
  const adminSession =
    verifyAdminSession(req);

  if (!adminSession) {
    return json(
      res,
      401,
      {
        success: false,
        authenticated: false,
        message:
          "Sessão Admin inválida ou expirada."
      }
    );
  }

  /*
   * =======================================================
   * CONSULTAR STATUS
   * =======================================================
   */

  if (
    body.check_status === true
  ) {
    return handleCheckStatus(
      req,
      res,
      body
    );
  }

  /*
   * =======================================================
   * CRIAR COMPRA
   * =======================================================
   */

  return handleCreatePurchase(
    req,
    res,
    body
  );
}
