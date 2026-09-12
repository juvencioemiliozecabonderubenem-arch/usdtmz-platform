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

import {
  getRealUsdtMznRate
} from "./admin-withdrawals.js";

export const config = {
  api: {
    bodyParser: false
  }
};

/*
 * ============================================================
 * CONFIGURAÇÃO DA COMPRA
 * ============================================================
 *
 * IMPORTANTE:
 *
 * NÃO EXISTE TAXA FIXA AQUI.
 *
 * A taxa USDT/MZN vem exclusivamente do motor cambial
 * real do API06.
 *
 * MIN / MAX são limites comerciais da compra.
 * NÃO são taxa de câmbio.
 */

const MIN = 64;
const MAX = 40000;

const METHODS = [
  "MPESA",
  "EMOLA"
];

/*
 * ============================================================
 * PAGAR
 * ============================================================
 */

const PAGAR_BASE = (
  process.env.PAGAR_API_BASE_URL ||
  process.env.PAGAR_BASE_URL ||
  "https://api.pagar.co.mz/api/v1"
).replace(/\/+$/, "");

/*
 * ============================================================
 * DATABASE
 * ============================================================
 */

function db() {
  return (
    process.env.URL_DO_BANCO_DE_DADOS ||
    process.env.POSTGRES_URL ||
    process.env.DATABASE_URL ||
    process.env.POSTGRES_URL_NON_POOLING ||
    process.env.DATABASE_URL_UNPOOLED
  );
}

/*
 * ============================================================
 * HELPERS
 * ============================================================
 */

const text = value =>
  String(value ?? "").trim();

const payment = value =>
  text(value).toUpperCase();

function orderId() {
  return (
    `USDTMZ-${Date.now()}-` +
    randomUUID()
      .replace(/-/g, "")
      .slice(0, 12)
      .toUpperCase()
  );
}

function header(req, name) {
  const value =
    req.headers?.[name];

  return Array.isArray(value)
    ? String(value[0] || "")
    : String(value || "");
}

function errorMessage(error) {
  return (
    error?.message ||
    error?.error ||
    error?.detail ||
    String(
      error ||
      "Erro desconhecido."
    )
  );
}

/*
 * ============================================================
 * COMPARAÇÃO EM TEMPO CONSTANTE
 * ============================================================
 */

function compare(a, b) {
  const A =
    Buffer.from(String(a));

  const B =
    Buffer.from(String(b));

  if (
    A.length !== B.length
  ) {
    return false;
  }

  return timingSafeEqual(
    A,
    B
  );
}

/*
 * ============================================================
 * BODY RAW
 * ============================================================
 */

async function raw(req) {
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

function json(rawBody) {
  try {
    return rawBody
      ? JSON.parse(rawBody)
      : {};
  } catch {
    return {};
  }
}

/*
 * ============================================================
 * PAGAR POST
 * ============================================================
 */

async function pagarPost(
  path,
  body,
  idempotencyKey
) {
  const key =
    process.env.PAGAR_API_KEY;

  const secret =
    process.env.PAGAR_SIGNING_SECRET;

  if (!key) {
    throw new Error(
      "PAGAR_API_KEY não configurada."
    );
  }

  if (!secret) {
    throw new Error(
      "PAGAR_SIGNING_SECRET não configurada."
    );
  }

  const url =
    `${PAGAR_BASE}${path}`;

  const timestamp =
    Date.now().toString();

  const nonce =
    randomBytes(18)
      .toString("base64url");

  const rawBody =
    JSON.stringify(body);

  const hash =
    createHash("sha256")
      .update(rawBody)
      .digest("hex");

  const canonical = [
    timestamp,
    nonce,
    "POST",
    new URL(url).pathname,
    hash
  ].join("\n");

  const signature =
    createHmac(
      "sha256",
      secret
    )
      .update(canonical)
      .digest("hex");

  const response =
    await fetch(url, {
      method: "POST",

      headers: {
        Accept:
          "application/json",

        "Content-Type":
          "application/json",

        Authorization:
          `Bearer ${key}`,

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

  const bodyText =
    await response.text();

  let data = {};

  try {
    data = bodyText
      ? JSON.parse(bodyText)
      : {};
  } catch {
    data = {
      raw: bodyText
    };
  }

  if (!response.ok) {
    const error =
      new Error(
        data?.message ||
        data?.error ||
        data?.detail ||
        bodyText ||
        `Pagar HTTP ${response.status}`
      );

    error.status =
      response.status;

    error.requestId =
      data?.requestId ||
      null;

    throw error;
  }

  return data;
}

/*
 * ============================================================
 * PAGAR GET
 * ============================================================
 */

async function pagarGet(path) {
  const key =
    process.env.PAGAR_API_KEY;

  if (!key) {
    throw new Error(
      "PAGAR_API_KEY não configurada."
    );
  }

  const response =
    await fetch(
      `${PAGAR_BASE}${path}`,
      {
        headers: {
          Accept:
            "application/json",

          Authorization:
            `Bearer ${key}`
        }
      }
    );

  const bodyText =
    await response.text();

  let data = {};

  try {
    data = bodyText
      ? JSON.parse(bodyText)
      : {};
  } catch {
    data = {
      raw: bodyText
    };
  }

  if (!response.ok) {
    throw new Error(
      data?.message ||
      data?.error ||
      data?.detail ||
      bodyText ||
      `Pagar HTTP ${response.status}`
    );
  }

  return data;
}

/*
 * ============================================================
 * PAGAR DATA EXTRACTION
 * ============================================================
 */

function extractPayment(data) {
  return (
    data?.payment ||
    data?.data?.payment ||
    data
  );
}

function paymentId(data) {
  const p =
    extractPayment(data);

  return text(
    p?.id ||
    data?.payment_id ||
    data?.paymentId ||
    data?.data?.payment_id ||
    data?.data?.paymentId
  );
}

function paymentStatus(data) {
  const p =
    extractPayment(data);

  return text(
    p?.status ||
    data?.status ||
    data?.payment_status ||
    data?.paymentStatus
  ).toUpperCase();
}

/*
 * ============================================================
 * WEBHOOK HELPERS
 * ============================================================
 */

function webhookEvent(
  req,
  body
) {
  return text(
    header(
      req,
      "pagar-event-id"
    ) ||
    body?.event_id ||
    body?.eventId ||
    body?.id
  );
}

function webhookType(body) {
  return text(
    body?.type ||
    body?.event ||
    body?.event_type ||
    body?.eventType
  ).toLowerCase();
}

function webhookPayment(body) {
  return (
    body?.payment ||
    body?.data?.payment ||
    body?.data ||
    body
  );
}

function webhookPaymentId(body) {
  const p =
    webhookPayment(body);

  return text(
    p?.id ||
    body?.payment_id ||
    body?.paymentId
  );
}

function reference(body) {
  const p =
    webhookPayment(body);

  return text(
    p?.reference ||
    body?.reference ||
    body?.data?.reference
  );
}

function webhookStatus(body) {
  const p =
    webhookPayment(body);

  return text(
    p?.status ||
    body?.status ||
    body?.payment_status ||
    body?.paymentStatus
  ).toUpperCase();
}

/*
 * ============================================================
 * PAGAR WEBHOOK SIGNATURE
 * ============================================================
 */

function verifyWebhook(
  req,
  rawBody
) {
  const secret =
    process.env.PAGAR_WEBHOOK_SECRET;

  const eventId =
    header(
      req,
      "pagar-event-id"
    );

  const signature =
    header(
      req,
      "pagar-signature"
    );

  if (
    !secret ||
    !eventId ||
    !signature
  ) {
    return false;
  }

  const parts =
    Object.fromEntries(
      signature
        .split(",")
        .map(item => {
          const index =
            item.indexOf("=");

          if (index === -1) {
            return [];
          }

          return [
            item
              .slice(0, index)
              .trim(),

            item
              .slice(index + 1)
              .trim()
          ];
        })
        .filter(
          item =>
            item.length
        )
    );

  const timestamp =
    parts.t;

  const received =
    parts.v1;

  if (
    !timestamp ||
    !received ||
    !/^\d+$/.test(timestamp)
  ) {
    return false;
  }

  if (
    !/^[a-f0-9]{64}$/i.test(
      received
    )
  ) {
    return false;
  }

  if (
    Math.abs(
      Date.now() / 1000 -
      Number(timestamp)
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

  return compare(
    received.toLowerCase(),
    expected.toLowerCase()
  );
}

/*
 * ============================================================
 * PROCESSAMENTO APÓS PAGAMENTO
 * ============================================================
 *
 * IMPORTANTE:
 *
 * Esta função NÃO cria USDT.
 * NÃO inventa liquidez.
 * NÃO recalcula a taxa.
 *
 * A ordem já contém:
 *
 * - MZN
 * - USDT
 * - taxa
 *
 * O processamento seguinte deve trabalhar com liquidez
 * USDT REAL.
 *
 * A execução efetiva continua no API de processamento.
 */

async function processPaid(
  sql,
  id
) {
  const rows =
    await sql`
      SELECT
        order_id,
        operation,
        status,
        amount,
        usdt_amount,
        rate,
        blockchain_tx_hash
      FROM orders
      WHERE order_id =
        ${id}
      LIMIT 1
    `;

  if (!rows.length) {
    throw new Error(
      "Ordem não encontrada."
    );
  }

  const order =
    rows[0];

  /*
   * Se já existe TX válida na ordem,
   * não tentar enviar novamente.
   */

  if (
    order.blockchain_tx_hash
  ) {
    return {
      status:
        "COMPLETED",

      tx_hash:
        order.blockchain_tx_hash
    };
  }

  /*
   * Confirmar operação correta.
   */

  if (
    String(order.operation)
      .toUpperCase() !==
    "BUY_USDT_ADMIN"
  ) {
    throw new Error(
      "Operação da ordem inválida."
    );
  }

  /*
   * Nunca processar sem pagamento confirmado.
   */

  if (
    String(order.status)
      .toUpperCase() !==
    "PAYMENT_CONFIRMED"
  ) {
    throw new Error(
      "O pagamento da ordem ainda não está confirmado."
    );
  }

  /*
   * Validar USDT gravado.
   */

  const storedUsdt =
    Number(
      order.usdt_amount
    );

  if (
    !Number.isFinite(
      storedUsdt
    ) ||
    storedUsdt <= 0
  ) {
    throw new Error(
      "Quantidade USDT inválida na ordem."
    );
  }

  /*
   * Validar taxa gravada.
   */

  const storedRate =
    Number(
      order.rate
    );

  if (
    !Number.isFinite(
      storedRate
    ) ||
    storedRate <= 0
  ) {
    throw new Error(
      "Taxa cambial inválida na ordem."
    );
  }

  /*
   * A execução real é delegada ao motor de transferência.
   *
   * Esse motor deverá garantir que o USDT enviado existe
   * realmente na carteira/liq uidez autorizada.
   */

  return processAdminPurchaseToBinanceInternal(
    id
  );
}

/*
 * ============================================================
 * WEBHOOK PAGAR
 * ============================================================
 */

async function webhook(
  req,
  res,
  sql,
  rawBody
) {
  /*
   * Primeiro validar assinatura.
   */

  if (
    !verifyWebhook(
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
    webhookEvent(
      req,
      body
    );

  const eventType =
    webhookType(body);

  const paymentIdValue =
    webhookPaymentId(body);

  const ref =
    reference(body);

  const paymentState =
    webhookStatus(body);

  if (
    !eventId ||
    !ref
  ) {
    return res.status(400).json({
      success: false,
      message:
        "Dados do webhook incompletos."
    });
  }

  /*
   * ========================================================
   * LOCALIZAR ORDEM PRIMEIRO
   * ========================================================
   *
   * Evita guardar permanentemente um evento para uma ordem
   * inexistente.
   */

  const orders =
    await sql`
      SELECT *
      FROM orders
      WHERE order_id =
        ${ref}
      LIMIT 1
    `;

  if (!orders.length) {
    return res.status(404).json({
      success: false,
      message:
        "Ordem USDTMZ não encontrada."
    });
  }

  const order =
    orders[0];

  /*
   * ========================================================
   * IDEMPOTÊNCIA DO WEBHOOK
   * ========================================================
   *
   * Se o evento já existir:
   *
   * - se já foi processado, responder duplicate;
   * - se ainda não foi processado, permitir nova tentativa.
   *
   * Isso é importante porque uma falha depois do INSERT
   * não pode bloquear definitivamente o processamento.
   */

  const insertedEvent =
    await sql`
      INSERT INTO pagar_webhook_events
      (
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
        ${paymentIdValue || null},
        ${ref},
        ${JSON.stringify(body)},
        NOW()
      )
      ON CONFLICT (event_id)
      DO NOTHING
      RETURNING event_id
    `;

  if (!insertedEvent.length) {
    const existing =
      await sql`
        SELECT
          event_id,
          processed_at
        FROM pagar_webhook_events
        WHERE event_id =
          ${eventId}
        LIMIT 1
      `;

    if (
      existing.length &&
      existing[0].processed_at
    ) {
      return res.status(200).json({
        success: true,
        duplicate: true,
        event_id:
          eventId
      });
    }

    /*
     * Evento existe mas não foi processado.
     *
     * Continuamos para permitir recuperação.
     */
  }

  /*
   * ========================================================
   * GUARDAR INFORMAÇÕES PAGAR
   * ========================================================
   */

  await sql`
    UPDATE orders SET
      pagar_payment_id =
        COALESCE(
          ${paymentIdValue || null},
          pagar_payment_id
        ),

      pagar_event_id =
        ${eventId},

      updated_at =
        NOW()

    WHERE order_id =
      ${ref}
  `;

  /*
   * ========================================================
   * JÁ CONCLUÍDA
   * ========================================================
   */

  if (
    order.blockchain_tx_hash
  ) {
    await sql`
      UPDATE pagar_webhook_events
      SET processed_at =
        NOW()
      WHERE event_id =
        ${eventId}
    `;

    return res.status(200).json({
      success: true,
      order_id:
        ref,
      status:
        "COMPLETED",
      tx_hash:
        order.blockchain_tx_hash
    });
  }

  /*
   * ========================================================
   * PAGAMENTO CONFIRMADO
   * ========================================================
   */

  if (
    eventType ===
      "payment.succeeded" ||
    paymentState ===
      "PAID"
  ) {
    await sql`
      UPDATE orders SET
        status =
          'PAYMENT_CONFIRMED',

        updated_at =
          NOW()

      WHERE order_id =
        ${ref}

      AND blockchain_tx_hash IS NULL
    `;

    try {
      const result =
        await processPaid(
          sql,
          ref
        );

      await sql`
        UPDATE pagar_webhook_events
        SET processed_at =
          NOW()
        WHERE event_id =
          ${eventId}
      `;

      return res.status(200).json({
        success: true,

        order_id:
          ref,

        status:
          result?.status ||
          "COMPLETED",

        tx_hash:
          result?.tx_hash ||
          null
      });

    } catch (error) {
      console.error(
        "PAGAR PAID -> USDT PROCESSING ERROR:",
        error
      );

      /*
       * O pagamento já foi confirmado.
       *
       * Não marcar FAILED porque a transferência USDT
       * pode ser processada posteriormente.
       *
       * O evento NÃO recebe processed_at aqui.
       * Assim uma nova entrega do webhook pode tentar
       * novamente.
       */

      await sql`
        UPDATE orders SET
          status =
            'PAYMENT_CONFIRMED',

          updated_at =
            NOW()

        WHERE order_id =
          ${ref}

        AND blockchain_tx_hash IS NULL
      `;

      return res.status(202).json({
        success: true,

        order_id:
          ref,

        status:
          "PAYMENT_CONFIRMED",

        message:
          "Pagamento confirmado; transferência USDT requer processamento."
      });
    }
  }

  /*
   * ========================================================
   * PAGAMENTO FALHOU
   * ========================================================
   */

  if (
    eventType ===
      "payment.failed" ||
    paymentState ===
      "FAILED"
  ) {
    await sql`
      UPDATE orders SET
        status =
          'FAILED',

        updated_at =
          NOW()

      WHERE order_id =
        ${ref}

      AND blockchain_tx_hash IS NULL
    `;

    await sql`
      UPDATE pagar_webhook_events
      SET processed_at =
        NOW()
      WHERE event_id =
        ${eventId}
    `;

    return res.status(200).json({
      success: true,

      order_id:
        ref,

      status:
        "FAILED"
    });
  }

  /*
   * ========================================================
   * CANCELADO
   * ========================================================
   */

  if (
    paymentState ===
    "CANCELLED"
  ) {
    await sql`
      UPDATE orders SET
        status =
          'CANCELLED',

        updated_at =
          NOW()

      WHERE order_id =
        ${ref}

      AND blockchain_tx_hash IS NULL
    `;

    await sql`
      UPDATE pagar_webhook_events
      SET processed_at =
        NOW()
      WHERE event_id =
        ${eventId}
    `;

    return res.status(200).json({
      success: true,

      order_id:
        ref,

      status:
        "CANCELLED"
    });
  }

  /*
   * ========================================================
   * PENDING / PROCESSING
   * ========================================================
   */

  await sql`
    UPDATE orders SET
      status =
        'PENDING',

      updated_at =
        NOW()

    WHERE order_id =
      ${ref}

    AND blockchain_tx_hash IS NULL
  `;

  await sql`
    UPDATE pagar_webhook_events
    SET processed_at =
      NOW()

    WHERE event_id =
      ${eventId}
  `;

  return res.status(200).json({
    success: true,

    order_id:
      ref,

    status:
      "PENDING"
  });
}

/*
 * ============================================================
 * MOTOR DE COTAÇÃO PARA NOVA COMPRA
 * ============================================================
 *
 * NÃO existe RATE = 64.
 *
 * O API07 pergunta ao motor cambial do API06.
 *
 * O motor deve:
 *
 * USD/MZN × USDT/USD
 *
 * e devolver uma taxa de mercado.
 *
 * Se todas as fontes falharem:
 *
 * NÃO existe fallback artificial.
 *
 * A compra fica indisponível.
 */

async function getPurchaseRate() {
  let rateData;

  try {
    rateData =
      await getRealUsdtMznRate(
        false
      );

  } catch (error) {
    console.error(
      "LIVE FX RATE ERROR:",
      error
    );

    throw new Error(
      "Cotação USDT/MZN temporariamente indisponível."
    );
  }

  const rate =
    Number(
      rateData?.rate
    );

  const marketRate =
    Number(
      rateData?.marketRate
    );

  /*
   * A taxa efetiva deve ser positiva.
   */

  if (
    !Number.isFinite(rate) ||
    rate <= 0
  ) {
    throw new Error(
      "Cotação USDT/MZN inválida."
    );
  }

  /*
   * Se o motor fornecer marketRate,
   * também validar.
   */

  if (
    rateData?.marketRate !==
      undefined &&
    (
      !Number.isFinite(
        marketRate
      ) ||
      marketRate <= 0
    )
  ) {
    throw new Error(
      "Taxa de mercado USDT/MZN inválida."
    );
  }

  /*
   * IMPORTANTE:
   *
   * Não aplicar spread aqui.
   *
   * Se o motor retornar spread = 0,
   * apenas informamos.
   *
   * Se o motor retornar spread diferente de zero,
   * API07 NÃO cria outro spread.
   */

  const spread =
    Number(
      rateData?.spread
    );

  const spreadPercent =
    Number(
      rateData?.spreadPercent
    );

  return {
    rate,

    marketRate:
      Number.isFinite(
        marketRate
      )
        ? marketRate
        : null,

    source:
      text(
        rateData?.source
      ) ||
      "UNKNOWN",

    updatedAt:
      rateData?.updatedAt ||
      new Date().toISOString(),

    fxUpdatedAt:
      rateData?.fxUpdatedAt ||
      null,

    spread:
      Number.isFinite(
        spread
      )
        ? spread
        : null,

    spreadPercent:
      Number.isFinite(
        spreadPercent
      )
        ? spreadPercent
        : null,

    warning:
      rateData?.warning ||
      null
  };
}

/*
 * ============================================================
 * CRIAR COMPRA
 * ============================================================
 */

async function createPurchase(
  req,
  res,
  sql
) {
  const rawBody =
    await raw(req);

  const body =
    json(rawBody);

  const name =
    text(
      body.name
    );

  const phone =
    text(
      body.phone
    );

  const method =
    payment(
      body.payment ||
      body.payment_method ||
      body.method
    );

  const amount =
    Number(
      body.amount ??
      body.amount_mzn ??
      body.valor
    );

  /*
   * ========================================================
   * VALIDAÇÃO DO CLIENTE
   * ========================================================
   */

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
      amount
    ) ||
    !Number.isInteger(
      amount
    )
  ) {
    return res.status(400).json({
      success: false,
      message:
        "O valor em MZN deve ser um número inteiro."
    });
  }

  if (
    amount < MIN
  ) {
    return res.status(400).json({
      success: false,
      message:
        `O valor mínimo é ${MIN} MZN.`
    });
  }

  if (
    amount > MAX
  ) {
    return res.status(400).json({
      success: false,
      message:
        `O valor máximo é ${MAX} MZN.`
    });
  }

  if (
    !METHODS.includes(
      method
    )
  ) {
    return res.status(400).json({
      success: false,
      message:
        "Método de pagamento inválido. Use MPESA ou EMOLA."
    });
  }

  /*
   * ========================================================
   * COTAÇÃO REAL
   * ========================================================
   *
   * PRIMEIRO:
   *   obter taxa.
   *
   * DEPOIS:
   *   calcular USDT.
   *
   * DEPOIS:
   *   gravar ordem.
   *
   * DEPOIS:
   *   criar pagamento.
   */

  let rateData;

  try {
    rateData =
      await getPurchaseRate();

  } catch (error) {
    console.error(
      "PURCHASE RATE UNAVAILABLE:",
      error
    );

    return res.status(503).json({
      success: false,
      message:
        "Cotação USDT/MZN temporariamente indisponível. Tente novamente dentro de alguns instantes."
    });
  }

  const rate =
    Number(
      rateData.rate
    );

  /*
   * ========================================================
   * CALCULAR USDT
   * ========================================================
   *
   * Exemplo:
   *
   * MZN = 640
   * taxa = 64
   *
   * USDT = 10
   *
   * A taxa real utilizada será aquela devolvida pelo
   * motor de mercado.
   */

  const usdtAmount =
    Number(
      (
        amount /
        rate
      ).toFixed(6)
    );

  if (
    !Number.isFinite(
      usdtAmount
    ) ||
    usdtAmount <= 0
  ) {
    return res.status(503).json({
      success: false,
      message:
        "Não foi possível calcular a quantidade USDT."
    });
  }

  /*
   * ========================================================
   * ID DA ORDEM
   * ========================================================
   */

  const id =
    orderId();

  /*
   * ========================================================
   * GRAVAR ORDEM
   * ========================================================
   *
   * A taxa é congelada para esta ordem.
   *
   * O mercado pode mudar depois.
   *
   * Isto impede que uma ordem já criada tenha a quantidade
   * USDT alterada silenciosamente.
   */

  try {
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
        ${id},
        ${name},
        ${phone},
        'BUY_USDT_ADMIN',
        ${method},
        ${amount},
        ${usdtAmount},
        ${rate},
        'PENDING',
        NOW(),
        NOW()
      )
    `;

  } catch (error) {
    console.error(
      "DATABASE CREATE ORDER ERROR:",
      error
    );

    return res.status(500).json({
      success: false,
      message:
        "Não foi possível criar a ordem no banco de dados."
    });
  }

  /*
   * ========================================================
   * CRIAR PAGAMENTO NA PAGAR
   * ========================================================
   */

  try {
    const pagar =
      await pagarPost(
        "/payments",

        {
          reference:
            id,

          title:
            "Compra de USDT",

          description:
            `Compra de USDT - ${id}`,

          amountMzn:
            amount,

          method,

          payerPhone:
            phone
        },

        /*
         * Idempotência.
         */

        `payment:${id}`
      );

    const p =
      extractPayment(
        pagar
      );

    const pagarPaymentId =
      paymentId(
        pagar
      );

    const pagarStatus =
      paymentStatus(
        pagar
      );

    /*
     * A Pagar deve devolver payment_id.
     */

    if (
      !pagarPaymentId
    ) {
      await sql`
        UPDATE orders
        SET
          status =
            'FAILED',

          updated_at =
            NOW()

        WHERE order_id =
          ${id}
      `;

      return res.status(502).json({
        success: false,

        message:
          "A Pagar respondeu sem payment_id.",

        order_id:
          id
      });
    }

    /*
     * ======================================================
     * ESTADO INTERNO
     * ======================================================
     */

    const internalStatus =
      pagarStatus ===
        "PAID"
        ? "PAYMENT_CONFIRMED"
        : "PENDING";

    await sql`
      UPDATE orders
      SET
        pagar_payment_id =
          ${pagarPaymentId},

        status =
          ${internalStatus},

        updated_at =
          NOW()

      WHERE order_id =
        ${id}
    `;

    /*
     * ======================================================
     * PAGAR JÁ CONFIRMOU?
     * ======================================================
     */

    if (
      pagarStatus ===
      "PAID"
    ) {
      try {
        const result =
          await processPaid(
            sql,
            id
          );

        return res.status(202).json({
          success: true,

          message:
            "Pagamento confirmado.",

          order: {
            order_id:
              id,

            amount_mzn:
              amount,

            usdt_amount:
              usdtAmount,

            rate:
              rate,

            payment:
              method,

            status:
              result?.status ||
              "COMPLETED"
          },

          rate_info: {
            source:
              rateData.source,

            market_rate:
              rateData.marketRate,

            updated_at:
              rateData.updatedAt,

            fx_updated_at:
              rateData.fxUpdatedAt,

            spread:
              rateData.spread,

            spread_percent:
              rateData.spreadPercent
          },

          pagar: {
            payment_id:
              pagarPaymentId,

            status:
              pagarStatus
          },

          tx_hash:
            result?.tx_hash ||
            null
        });

      } catch (error) {
        console.error(
          "PAID -> USDT PROCESSING ERROR:",
          error
        );

        return res.status(202).json({
          success: true,

          message:
            "Pagamento confirmado; transferência USDT requer processamento.",

          order: {
            order_id:
              id,

            amount_mzn:
              amount,

            usdt_amount:
              usdtAmount,

            rate:
              rate,

            payment:
              method,

            status:
              "PAYMENT_CONFIRMED"
          },

          rate_info: {
            source:
              rateData.source,

            market_rate:
              rateData.marketRate,

            updated_at:
              rateData.updatedAt,

            fx_updated_at:
              rateData.fxUpdatedAt,

            spread:
              rateData.spread,

            spread_percent:
              rateData.spreadPercent
          },

          pagar: {
            payment_id:
              pagarPaymentId,

            status:
              pagarStatus
          }
        });
      }
    }

    /*
     * ======================================================
     * PAGAMENTO PENDING / PROCESSING
     * ======================================================
     */

    return res.status(202).json({
      success: true,

      message:
        "Pagamento enviado para a Pagar. Aguarde a confirmação.",

      order: {
        order_id:
          id,

        amount_mzn:
          amount,

        usdt_amount:
          usdtAmount,

        rate:
          rate,

        payment:
          method,

        status:
          "PENDING"
      },

      rate_info: {
        source:
          rateData.source,

        market_rate:
          rateData.marketRate,

        updated_at:
          rateData.updatedAt,

        fx_updated_at:
          rateData.fxUpdatedAt,

        spread:
          rateData.spread,

        spread_percent:
          rateData.spreadPercent
      },

      pagar: {
        payment_id:
          pagarPaymentId,

        status:
          pagarStatus ||
          "PROCESSING"
      }
    });

  } catch (error) {
    console.error(
      "PAGAR CREATE PAYMENT ERROR:",
      error
    );

    /*
     * Não afirmar que o pagamento falhou apenas porque
     * houve erro de comunicação.
     *
     * A ordem permanece PENDING.
     */

    await sql`
      UPDATE orders
      SET
        status =
          'PENDING',

        updated_at =
          NOW()

      WHERE order_id =
        ${id}

      AND blockchain_tx_hash IS NULL
    `;

    const errorStatus =
      Number(
        error?.status || 0
      );

    const statusCode =
      errorStatus >= 400 &&
      errorStatus < 500
        ? 502
        : 202;

    return res.status(
      statusCode
    ).json({
      success: false,

      message:
        "A criação do pagamento ficou inconclusiva. A ordem permanece PENDING.",

      order_id:
        id,

      status:
        "PENDING"
    });
  }
}

/*
 * ============================================================
 * CONSULTAR ESTADO DA ORDEM
 * ============================================================
 *
 * Esta rota é interna.
 *
 * O segredo NÃO deve ser exposto ao cliente.
 */

async function statusCheck(
  req,
  res,
  sql
) {
  const secret =
    process.env.PAGAR_SIGNING_SECRET;

  const received =
    header(
      req,
      "x-pagar-secret"
    );

  if (
    !secret ||
    !received ||
    !compare(
      received,
      secret
    )
  ) {
    return res.status(401).json({
      success: false,
      message:
        "Não autorizado."
    });
  }

  const id =
    text(
      req.query?.order_id ||
      req.query?.orderId
    );

  if (!id) {
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
        blockchain_tx_hash,
        amount,
        usdt_amount,
        rate
      FROM orders
      WHERE order_id =
        ${id}
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

  /*
   * ========================================================
   * JÁ CONCLUÍDA
   * ========================================================
   */

  if (
    order.blockchain_tx_hash
  ) {
    return res.status(200).json({
      success: true,

      order_id:
        id,

      status:
        "COMPLETED",

      tx_hash:
        order.blockchain_tx_hash,

      amount_mzn:
        Number(
          order.amount
        ),

      usdt_amount:
        Number(
          order.usdt_amount
        ),

      rate:
        Number(
          order.rate
        )
    });
  }

  /*
   * ========================================================
   * SEM PAGAMENTO
   * ========================================================
   */

  if (
    !order.pagar_payment_id
  ) {
    return res.status(409).json({
      success: false,

      message:
        "A ordem ainda não possui pagar_payment_id."
    });
  }

  /*
   * ========================================================
   * CONSULTAR PAGAR
   * ========================================================
   */

  const data =
    await pagarGet(
      `/payments/${encodeURIComponent(
        order.pagar_payment_id
      )}`
    );

  const pagarStatus =
    paymentStatus(
      data
    );

  /*
   * ========================================================
   * PAGO
   * ========================================================
   */

  if (
    pagarStatus ===
    "PAID"
  ) {
    await sql`
      UPDATE orders
      SET
        status =
          'PAYMENT_CONFIRMED',

        updated_at =
          NOW()

      WHERE order_id =
        ${id}

      AND blockchain_tx_hash IS NULL
    `;

    try {
      const result =
        await processPaid(
          sql,
          id
        );

      return res.status(200).json({
        success: true,

        order_id:
          id,

        status:
          result?.status ||
          "COMPLETED",

        tx_hash:
          result?.tx_hash ||
          null,

        amount_mzn:
          Number(
            order.amount
          ),

        usdt_amount:
          Number(
            order.usdt_amount
          ),

        rate:
          Number(
            order.rate
          )
      });

    } catch (error) {
      console.error(
        "STATUS -> USDT PROCESSING ERROR:",
        error
      );

      return res.status(202).json({
        success: true,

        order_id:
          id,

        status:
          "PAYMENT_CONFIRMED",

        message:
          "Pagamento confirmado; transferência USDT requer processamento.",

        amount_mzn:
          Number(
            order.amount
          ),

        usdt_amount:
          Number(
            order.usdt_amount
          ),

        rate:
          Number(
            order.rate
          )
      });
    }
  }

  /*
   * ========================================================
   * FALHOU / CANCELADO / PENDING
   * ========================================================
   */

  const internalStatus =
    pagarStatus ===
      "FAILED"
      ? "FAILED"
      : pagarStatus ===
          "CANCELLED"
        ? "CANCELLED"
        : "PENDING";

  await sql`
    UPDATE orders
    SET
      status =
        ${internalStatus},

      updated_at =
        NOW()

    WHERE order_id =
      ${id}

    AND blockchain_tx_hash IS NULL
  `;

  return res.status(200).json({
    success: true,

    order_id:
      id,

    payment_status:
      pagarStatus ||
      "PENDING",

    status:
      internalStatus,

    amount_mzn:
      Number(
        order.amount
      ),

    usdt_amount:
      Number(
        order.usdt_amount
      ),

    rate:
      Number(
        order.rate
      )
  });
}

/*
 * ============================================================
 * HANDLER PRINCIPAL
 * ============================================================
 */

export default async function handler(
  req,
  res
) {
  try {
    const databaseUrl =
      db();

    if (!databaseUrl) {
      return res.status(500).json({
        success: false,

        message:
          "Banco de dados não configurado."
      });
    }

    const sql =
      neon(
        databaseUrl
      );

    /*
     * ======================================================
     * WEBHOOK PAGAR
     * ======================================================
     */

    if (
      req.method ===
        "POST" &&
      header(
        req,
        "pagar-event-id"
      ) &&
      header(
        req,
        "pagar-signature"
      )
    ) {
      const rawBody =
        await raw(req);

      return webhook(
        req,
        res,
        sql,
        rawBody
      );
    }

    /*
     * ======================================================
     * CONSULTA DE STATUS
     * ======================================================
     */

    if (
      req.method ===
        "GET" &&
      (
        req.query?.order_id ||
        req.query?.orderId
      )
    ) {
      return statusCheck(
        req,
        res,
        sql
      );
    }

    /*
     * ======================================================
     * NOVA COMPRA
     * ======================================================
     */

    if (
      req.method ===
      "POST"
    ) {
      return createPurchase(
        req,
        res,
        sql
      );
    }

    /*
     * ======================================================
     * MÉTODO NÃO PERMITIDO
     * ======================================================
     */

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

    /*
     * Nunca devolver stack trace ou detalhes internos
     * para o cliente em produção.
     */

    return res.status(500).json({
      success: false,

      message:
        "Erro interno ao processar a operação."
    });
  }
}
