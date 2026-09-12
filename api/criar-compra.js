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

export const config = { api: { bodyParser: false } };

/*
 * ============================================================
 * CONFIGURAÇÃO DA COMPRA
 * ============================================================
 *
 * IMPORTANTE:
 * RATE FIXA FOI REMOVIDA.
 *
 * A taxa agora vem do motor cambial real do API06.
 *
 * MIN e MAX são limites comerciais da compra,
 * NÃO são taxa de câmbio.
 */

const MIN = 64;
const MAX = 40000;

const METHODS = ["MPESA", "EMOLA"];

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

const text = v => String(v ?? "").trim();

const payment = v =>
  text(v).toUpperCase();

function orderId() {
  return `USDTMZ-${Date.now()}-${randomUUID()
    .replace(/-/g, "")
    .slice(0, 12)
    .toUpperCase()}`;
}

function header(req, name) {
  const v = req.headers?.[name];

  return Array.isArray(v)
    ? String(v[0] || "")
    : String(v || "");
}

function errorMessage(e) {
  return (
    e?.message ||
    e?.error ||
    e?.detail ||
    String(e || "Erro desconhecido.")
  );
}

/*
 * Comparação em tempo constante.
 */
function compare(a, b) {
  const A = Buffer.from(String(a));
  const B = Buffer.from(String(b));

  return (
    A.length === B.length &&
    timingSafeEqual(A, B)
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
    randomBytes(18).toString("base64url");

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
        Accept: "application/json",
        "Content-Type": "application/json",

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
    const e = new Error(
      data?.message ||
      data?.error ||
      data?.detail ||
      bodyText ||
      `Pagar HTTP ${response.status}`
    );

    e.status =
      response.status;

    e.requestId =
      data?.requestId || null;

    throw e;
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
          Accept: "application/json",
          Authorization:
            `Bearer ${key}`
        }
      }
    );

  const t =
    await response.text();

  let data = {};

  try {
    data = t
      ? JSON.parse(t)
      : {};
  } catch {
    data = {
      raw: t
    };
  }

  if (!response.ok) {
    throw new Error(
      data?.message ||
      data?.error ||
      data?.detail ||
      t ||
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

function webhookEvent(req, body) {
  return text(
    header(req, "pagar-event-id") ||
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
    header(req, "pagar-event-id");

  const sig =
    header(req, "pagar-signature");

  if (
    !secret ||
    !eventId ||
    !sig
  ) {
    return false;
  }

  const parts =
    Object.fromEntries(
      sig
        .split(",")
        .map(x => {
          const i =
            x.indexOf("=");

          return i === -1
            ? []
            : [
                x
                  .slice(0, i)
                  .trim(),

                x
                  .slice(i + 1)
                  .trim()
              ];
        })
        .filter(
          x => x.length
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
    !/^[a-f0-9]{64}$/i.test(received)
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
 * Esta função NÃO calcula a taxa.
 *
 * A taxa e o USDT já ficam gravados na ordem.
 *
 * O terceiro API será responsável pelo processamento
 * financeiro/entrega propriamente dito.
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
      WHERE order_id = ${id}
      LIMIT 1
    `;

  if (!rows.length) {
    throw new Error(
      "Ordem não encontrada."
    );
  }

  const o =
    rows[0];

  if (o.blockchain_tx_hash) {
    return {
      status: "COMPLETED",
      tx_hash:
        o.blockchain_tx_hash
    };
  }

  if (
    String(o.operation)
      .toUpperCase() !==
    "BUY_USDT_ADMIN"
  ) {
    throw new Error(
      "Operação da ordem inválida."
    );
  }

  /*
   * Nunca processar uma ordem sem pagamento confirmado.
   */
  if (
    String(o.status)
      .toUpperCase() !==
    "PAYMENT_CONFIRMED"
  ) {
    throw new Error(
      "O pagamento da ordem ainda não está confirmado."
    );
  }

  /*
   * Segurança:
   * quantidade USDT e taxa devem existir no banco.
   */
  const storedUsdt =
    Number(o.usdt_amount);

  const storedRate =
    Number(o.rate);

  if (
    !Number.isFinite(storedUsdt) ||
    storedUsdt <= 0
  ) {
    throw new Error(
      "Quantidade USDT inválida na ordem."
    );
  }

  if (
    !Number.isFinite(storedRate) ||
    storedRate <= 0
  ) {
    throw new Error(
      "Taxa cambial inválida na ordem."
    );
  }

  /*
   * O motor de execução será analisado na terceira API.
   */
  return processAdminPurchaseToBinanceInternal(
    id
  );
}

/*
 * ============================================================
 * WEBHOOK
 * ============================================================
 */

async function webhook(
  req,
  res,
  sql,
  rawBody
) {
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

  const pId =
    webhookPaymentId(body);

  const ref =
    reference(body);

  const pStatus =
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
   * IDEMPOTÊNCIA DO WEBHOOK
   * ========================================================
   *
   * Em vez de:
   *
   * SELECT -> INSERT
   *
   * fazemos INSERT ... ON CONFLICT ... RETURNING.
   *
   * Assim duas entregas simultâneas do mesmo evento não
   * devem passar ambas para o processamento.
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
        ${pId || null},
        ${ref},
        ${JSON.stringify(body)},
        NOW()
      )
      ON CONFLICT (event_id)
      DO NOTHING
      RETURNING event_id
    `;

  if (!insertedEvent.length) {
    return res.status(200).json({
      success: true,
      duplicate: true,
      event_id: eventId
    });
  }

  /*
   * Localizar ordem.
   */

  const orders =
    await sql`
      SELECT *
      FROM orders
      WHERE order_id = ${ref}
      LIMIT 1
    `;

  if (!orders.length) {
    return res.status(404).json({
      success: false,
      message:
        "Ordem USDTMZ não encontrada."
    });
  }

  const o =
    orders[0];

  /*
   * Guardar informações do pagamento.
   */

  await sql`
    UPDATE orders SET
      pagar_payment_id =
        COALESCE(
          ${pId || null},
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
   * Já concluída.
   */

  if (o.blockchain_tx_hash) {
    await sql`
      UPDATE pagar_webhook_events
      SET processed_at = NOW()
      WHERE event_id = ${eventId}
    `;

    return res.status(200).json({
      success: true,
      order_id: ref,
      status: "COMPLETED",
      tx_hash:
        o.blockchain_tx_hash
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
    pStatus === "PAID"
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
        order_id: ref,
        status:
          result?.status ||
          "COMPLETED",
        tx_hash:
          result?.tx_hash ||
          null
      });

    } catch (e) {
      console.error(
        "PAGAR PAID -> BINANCE ERROR:",
        e
      );

      /*
       * O dinheiro foi confirmado.
       *
       * Não marcamos FAILED simplesmente porque a entrega
       * do USDT falhou.
       *
       * A ordem continua PAYMENT_CONFIRMED para permitir
       * processamento posterior.
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
        order_id: ref,
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
    pStatus === "FAILED"
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
      order_id: ref,
      status: "FAILED"
    });
  }

  /*
   * ========================================================
   * CANCELADO
   * ========================================================
   */

  if (
    pStatus ===
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
      order_id: ref,
      status: "CANCELLED"
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
    order_id: ref,
    status: "PENDING"
  });
}

/*
 * ============================================================
 * MOTOR DE COTAÇÃO PARA NOVA COMPRA
 * ============================================================
 *
 * A cotação NÃO é inventada aqui.
 *
 * API07 pede ao motor cambial do API06.
 *
 * Se o motor não conseguir uma cotação válida,
 * a compra NÃO é criada.
 *
 * Isto evita vender USDT com uma taxa falsa.
 */

async function getPurchaseRate() {
  let rateData;

  try {
    /*
     * false = respeitar o cache controlado do motor cambial.
     *
     * O motor continua sendo atualizado periodicamente,
     * mas não vamos bombardear os provedores externos a
     * cada clique de cada cliente.
     */
    rateData =
      await getRealUsdtMznRate(
        false
      );

  } catch (e) {
    console.error(
      "LIVE FX RATE ERROR:",
      e
    );

    throw new Error(
      "Cotação USDT/MZN temporariamente indisponível."
    );
  }

  const rate =
    Number(rateData?.rate);

  const marketRate =
    Number(
      rateData?.marketRate
    );

  if (
    !Number.isFinite(rate) ||
    rate <= 0
  ) {
    throw new Error(
      "Cotação USDT/MZN inválida."
    );
  }

  /*
   * Se existir marketRate, também validamos.
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

  return {
    rate,
    marketRate:
      Number.isFinite(marketRate)
        ? marketRate
        : null,

    source:
      text(
        rateData?.source
      ) || "UNKNOWN",

    updatedAt:
      rateData?.updatedAt ||
      new Date().toISOString(),

    fxUpdatedAt:
      rateData?.fxUpdatedAt ||
      null,

    spread:
      Number.isFinite(
        Number(rateData?.spread)
      )
        ? Number(rateData.spread)
        : null,

    spreadPercent:
      Number.isFinite(
        Number(
          rateData?.spreadPercent
        )
      )
        ? Number(
            rateData.spreadPercent
          )
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
    text(body.name);

  const phone =
    text(body.phone);

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
    !Number.isFinite(amount) ||
    !Number.isInteger(amount)
  ) {
    return res.status(400).json({
      success: false,
      message:
        "O valor em MZN deve ser um número inteiro."
    });
  }

  if (amount < MIN) {
    return res.status(400).json({
      success: false,
      message:
        `O valor mínimo é ${MIN} MZN.`
    });
  }

  if (amount > MAX) {
    return res.status(400).json({
      success: false,
      message:
        `O valor máximo é ${MAX} MZN.`
    });
  }

  if (!METHODS.includes(method)) {
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
   * PRIMEIRO calculamos a taxa.
   *
   * DEPOIS criamos a ordem.
   *
   * Assim a ordem fica gravada com a cotação exata
   * utilizada naquela compra.
   */

  let rateData;

  try {
    rateData =
      await getPurchaseRate();

  } catch (e) {
    console.error(
      "PURCHASE RATE UNAVAILABLE:",
      e
    );

    return res.status(503).json({
      success: false,
      message:
        "Cotação USDT/MZN temporariamente indisponível. Tente novamente dentro de alguns instantes."
    });
  }

  const rate =
    Number(rateData.rate);

  /*
   * Quantidade final de USDT.
   *
   * 6 casas porque USDT TRC20 usa 6 decimais.
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

  let created;

  /*
   * ========================================================
   * GRAVAR ORDEM
   * ========================================================
   *
   * Guardamos:
   *
   * amount       = MZN pago
   * usdt_amount  = USDT prometido
   * rate         = taxa efetivamente usada
   *
   * Desta forma a ordem não muda simplesmente porque o
   * mercado mudou depois.
   */

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
        RETURNING
          order_id,
          name,
          phone,
          payment,
          amount,
          usdt_amount,
          rate,
          status,
          created_at
      `;

  } catch (e) {
    console.error(
      "DATABASE CREATE ORDER ERROR:",
      e
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
          reference: id,

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
         * Idempotency-Key exclusiva.
         *
         * Se a mesma requisição for repetida, a Pagar
         * recebe a mesma chave.
         */
        `payment:${id}`
      );

    const p =
      extractPayment(
        pagar
      );

    const pId =
      paymentId(
        pagar
      );

    const pStatus =
      paymentStatus(
        pagar
      );

    /*
     * A Pagar precisa devolver um payment_id.
     */

    if (!pId) {
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
        order_id: id
      });
    }

    /*
     * ======================================================
     * ESTADO INTERNO
     * ======================================================
     */

    const internalStatus =
      pStatus === "PAID"
        ? "PAYMENT_CONFIRMED"
        : "PENDING";

    await sql`
      UPDATE orders
      SET
        pagar_payment_id =
          ${pId},

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
      pStatus === "PAID"
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
              pId,

            status:
              pStatus,

            data:
              p
          },

          tx_hash:
            result?.tx_hash ||
            null
        });

      } catch (e) {
        console.error(
          "PAID -> BINANCE ERROR:",
          e
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
              pId,

            status:
              pStatus
          }
        });
      }
    }

    /*
     * ======================================================
     * PAGAMENTO AINDA PENDING / PROCESSING
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
          pId,

        status:
          pStatus ||
          "PROCESSING",

        data:
          p
      }
    });

  } catch (e) {
    console.error(
      "PAGAR CREATE PAYMENT ERROR:",
      e
    );

    /*
     * Não podemos afirmar que o pagamento falhou
     * se houve erro de comunicação.
     *
     * Mantemos PENDING.
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

    const statusCode =
      Number(
        e?.status || 0
      ) >= 400 &&
      Number(
        e?.status || 0
      ) < 500
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
        "PENDING",

      detail:
        errorMessage(e),

      request_id:
        e?.requestId ||
        null
    });
  }
}

/*
 * ============================================================
 * CONSULTAR ESTADO DA ORDEM
 * ============================================================
 */

async function statusCheck(
  req,
  res,
  sql
) {
  /*
   * Esta rota é protegida pelo segredo interno.
   */

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

  const o =
    rows[0];

  /*
   * Já concluída.
   */

  if (
    o.blockchain_tx_hash
  ) {
    return res.status(200).json({
      success: true,

      order_id:
        id,

      status:
        "COMPLETED",

      tx_hash:
        o.blockchain_tx_hash,

      amount_mzn:
        Number(o.amount),

      usdt_amount:
        Number(o.usdt_amount),

      rate:
        Number(o.rate)
    });
  }

  /*
   * Sem pagamento ainda.
   */

  if (
    !o.pagar_payment_id
  ) {
    return res.status(409).json({
      success: false,
      message:
        "A ordem ainda não possui pagar_payment_id."
    });
  }

  /*
   * Consultar Pagar.
   */

  const data =
    await pagarGet(
      `/payments/${encodeURIComponent(
        o.pagar_payment_id
      )}`
    );

  const pStatus =
    paymentStatus(
      data
    );

  /*
   * ========================================================
   * PAGO
   * ========================================================
   */

  if (
    pStatus === "PAID"
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
          Number(o.amount),

        usdt_amount:
          Number(o.usdt_amount),

        rate:
          Number(o.rate)
      });

    } catch (e) {
      console.error(
        "STATUS -> BINANCE ERROR:",
        e
      );

      return res.status(202).json({
        success: true,

        order_id:
          id,

        status:
          "PAYMENT_CONFIRMED",

        message:
          "Pagamento confirmado; transferência requer processamento.",

        amount_mzn:
          Number(o.amount),

        usdt_amount:
          Number(o.usdt_amount),

        rate:
          Number(o.rate)
      });
    }
  }

  /*
   * ========================================================
   * FALHOU / CANCELADO / PENDING
   * ========================================================
   */

  const internalStatus =
    pStatus === "FAILED"
      ? "FAILED"
      : pStatus === "CANCELLED"
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
      pStatus ||
      "PENDING",

    status:
      internalStatus,

    amount_mzn:
      Number(o.amount),

    usdt_amount:
      Number(o.usdt_amount),

    rate:
      Number(o.rate)
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
      neon(databaseUrl);

    /*
     * ======================================================
     * WEBHOOK PAGAR
     * ======================================================
     */

    if (
      req.method === "POST" &&
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
      req.method === "GET" &&
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
      req.method === "POST"
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

  } catch (e) {
    console.error(
      "CREATE PURCHASE FATAL ERROR:",
      e
    );

    return res.status(500).json({
      success: false,
      message:
        "Erro interno ao processar a operação.",
      detail:
        errorMessage(e)
    });
  }
}
