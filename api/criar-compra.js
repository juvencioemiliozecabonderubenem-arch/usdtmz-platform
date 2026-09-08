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

export const config = { api: { bodyParser: false } };

const RATE = 64;
const MIN = 64;
const MAX = 40000;
const METHODS = ["MPESA", "EMOLA"];

const PAGAR_BASE = (
  process.env.PAGAR_API_BASE_URL ||
  process.env.PAGAR_BASE_URL ||
  "https://api.pagar.co.mz/api/v1"
).replace(/\/+$/, "");

function db() {
  return process.env.URL_DO_BANCO_DE_DADOS ||
    process.env.POSTGRES_URL ||
    process.env.DATABASE_URL ||
    process.env.POSTGRES_URL_NON_POOLING ||
    process.env.DATABASE_URL_UNPOOLED;
}

const text = v => String(v ?? "").trim();
const payment = v => text(v).toUpperCase();
const usdt = m => Number((Number(m) / RATE).toFixed(6));

function orderId() {
  return `USDTMZ-${Date.now()}-${randomUUID()
    .replace(/-/g, "").slice(0, 12).toUpperCase()}`;
}

function header(req, name) {
  const v = req.headers?.[name];
  return Array.isArray(v) ? String(v[0] || "") : String(v || "");
}

function errorMessage(e) {
  return e?.message || e?.error || e?.detail || String(e || "Erro desconhecido.");
}

function compare(a, b) {
  const A = Buffer.from(String(a));
  const B = Buffer.from(String(b));
  return A.length === B.length && timingSafeEqual(A, B);
}

async function raw(req) {
  if (Buffer.isBuffer(req.body)) return req.body.toString("utf8");
  if (typeof req.body === "string") return req.body;

  let body = "";
  for await (const chunk of req) body += chunk;
  return body;
}

function json(rawBody) {
  try { return rawBody ? JSON.parse(rawBody) : {}; }
  catch { return {}; }
}

async function pagarPost(path, body, idempotencyKey) {
  const key = process.env.PAGAR_API_KEY;
  const secret = process.env.PAGAR_SIGNING_SECRET;

  if (!key) throw new Error("PAGAR_API_KEY não configurada.");
  if (!secret) throw new Error("PAGAR_SIGNING_SECRET não configurada.");

  const url = `${PAGAR_BASE}${path}`;
  const timestamp = Date.now().toString();
  const nonce = randomBytes(18).toString("base64url");
  const rawBody = JSON.stringify(body);
  const hash = createHash("sha256").update(rawBody).digest("hex");

  const canonical = [
    timestamp,
    nonce,
    "POST",
    new URL(url).pathname,
    hash
  ].join("\n");

  const signature = createHmac("sha256", secret)
    .update(canonical)
    .digest("hex");

  const response = await fetch(url, {
    method: "POST",
    headers: {
      Accept: "application/json",
      "Content-Type": "application/json",
      Authorization: `Bearer ${key}`,
      "Idempotency-Key": idempotencyKey,
      "X-Pagar-Timestamp": timestamp,
      "X-Pagar-Nonce": nonce,
      "X-Pagar-Signature": `v1=${signature}`
    },
    body: rawBody
  });

  const bodyText = await response.text();
  let data = {};

  try { data = bodyText ? JSON.parse(bodyText) : {}; }
  catch { data = { raw: bodyText }; }

  if (!response.ok) {
    const e = new Error(
      data?.message || data?.error || data?.detail ||
      bodyText || `Pagar HTTP ${response.status}`
    );
    e.status = response.status;
    e.requestId = data?.requestId || null;
    throw e;
  }

  return data;
}

async function pagarGet(path) {
  const key = process.env.PAGAR_API_KEY;
  if (!key) throw new Error("PAGAR_API_KEY não configurada.");

  const response = await fetch(`${PAGAR_BASE}${path}`, {
    headers: {
      Accept: "application/json",
      Authorization: `Bearer ${key}`
    }
  });

  const t = await response.text();
  let data = {};
  try { data = t ? JSON.parse(t) : {}; }
  catch { data = { raw: t }; }

  if (!response.ok) {
    throw new Error(
      data?.message || data?.error || data?.detail ||
      t || `Pagar HTTP ${response.status}`
    );
  }

  return data;
}

function extractPayment(data) {
  return data?.payment || data?.data?.payment || data;
}

function paymentId(data) {
  const p = extractPayment(data);
  return text(
    p?.id || data?.payment_id || data?.paymentId ||
    data?.data?.payment_id || data?.data?.paymentId
  );
}

function paymentStatus(data) {
  const p = extractPayment(data);
  return text(
    p?.status || data?.status ||
    data?.payment_status || data?.paymentStatus
  ).toUpperCase();
}

function webhookEvent(req, body) {
  return text(
    header(req, "pagar-event-id") ||
    body?.event_id || body?.eventId || body?.id
  );
}

function webhookType(body) {
  return text(
    body?.type || body?.event ||
    body?.event_type || body?.eventType
  ).toLowerCase();
}

function webhookPayment(body) {
  return body?.payment || body?.data?.payment || body?.data || body;
}

function webhookPaymentId(body) {
  const p = webhookPayment(body);
  return text(p?.id || body?.payment_id || body?.paymentId);
}

function reference(body) {
  const p = webhookPayment(body);
  return text(p?.reference || body?.reference || body?.data?.reference);
}

function webhookStatus(body) {
  const p = webhookPayment(body);
  return text(
    p?.status || body?.status ||
    body?.payment_status || body?.paymentStatus
  ).toUpperCase();
}

function verifyWebhook(req, rawBody) {
  const secret = process.env.PAGAR_WEBHOOK_SECRET;
  const eventId = header(req, "pagar-event-id");
  const sig = header(req, "pagar-signature");

  if (!secret || !eventId || !sig) return false;

  const parts = Object.fromEntries(
    sig.split(",").map(x => {
      const i = x.indexOf("=");
      return i === -1 ? [] : [
        x.slice(0, i).trim(),
        x.slice(i + 1).trim()
      ];
    }).filter(x => x.length)
  );

  const timestamp = parts.t;
  const received = parts.v1;

  if (!timestamp || !received || !/^\d+$/.test(timestamp)) return false;
  if (!/^[a-f0-9]{64}$/i.test(received)) return false;

  if (Math.abs(Date.now() / 1000 - Number(timestamp)) > 300) return false;

  const expected = createHmac("sha256", secret)
    .update(`${timestamp}.${rawBody}`)
    .digest("hex");

  return compare(received.toLowerCase(), expected.toLowerCase());
}

async function processPaid(sql, id) {
  const rows = await sql`
    SELECT order_id, operation, status, usdt_amount, blockchain_tx_hash
    FROM orders
    WHERE order_id = ${id}
    LIMIT 1
  `;

  if (!rows.length) throw new Error("Ordem não encontrada.");

  const o = rows[0];

  if (o.blockchain_tx_hash) {
    return { status: "COMPLETED", tx_hash: o.blockchain_tx_hash };
  }

  if (String(o.operation).toUpperCase() !== "BUY_USDT_ADMIN") {
    throw new Error("Operação da ordem inválida.");
  }

  return processAdminPurchaseToBinanceInternal(id);
}

async function webhook(req, res, sql, rawBody) {
  if (!verifyWebhook(req, rawBody)) {
    return res.status(401).json({
      success: false,
      message: "Assinatura do webhook inválida."
    });
  }

  let body;
  try { body = JSON.parse(rawBody); }
  catch {
    return res.status(400).json({
      success: false,
      message: "Webhook JSON inválido."
    });
  }

  const eventId = webhookEvent(req, body);
  const eventType = webhookType(body);
  const pId = webhookPaymentId(body);
  const ref = reference(body);
  const pStatus = webhookStatus(body);

  if (!eventId || !ref) {
    return res.status(400).json({
      success: false,
      message: "Dados do webhook incompletos."
    });
  }

  const duplicate = await sql`
    SELECT event_id FROM pagar_webhook_events
    WHERE event_id = ${eventId}
    LIMIT 1
  `;

  if (duplicate.length) {
    return res.status(200).json({
      success: true,
      duplicate: true,
      event_id: eventId
    });
  }

  const orders = await sql`
    SELECT * FROM orders
    WHERE order_id = ${ref}
    LIMIT 1
  `;

  if (!orders.length) {
    return res.status(404).json({
      success: false,
      message: "Ordem USDTMZ não encontrada."
    });
  }

  const o = orders[0];

  await sql`
    INSERT INTO pagar_webhook_events
    (event_id,event_type,payment_id,reference,payload,created_at)
    VALUES (
      ${eventId},
      ${eventType || "UNKNOWN"},
      ${pId || null},
      ${ref},
      ${JSON.stringify(body)},
      NOW()
    )
    ON CONFLICT (event_id) DO NOTHING
  `;

  await sql`
    UPDATE orders SET
      pagar_payment_id = COALESCE(${pId || null}, pagar_payment_id),
      pagar_event_id = ${eventId},
      updated_at = NOW()
    WHERE order_id = ${ref}
  `;

  if (o.blockchain_tx_hash) {
    return res.status(200).json({
      success: true,
      order_id: ref,
      status: "COMPLETED",
      tx_hash: o.blockchain_tx_hash
    });
  }

  if (eventType === "payment.succeeded" || pStatus === "PAID") {
    await sql`
      UPDATE orders SET
        status = 'PAYMENT_CONFIRMED',
        updated_at = NOW()
      WHERE order_id = ${ref}
      AND blockchain_tx_hash IS NULL
    `;

    try {
      const result = await processPaid(sql, ref);

      await sql`
        UPDATE pagar_webhook_events
        SET processed_at = NOW()
        WHERE event_id = ${eventId}
      `;

      return res.status(200).json({
        success: true,
        order_id: ref,
        status: result?.status || "COMPLETED",
        tx_hash: result?.tx_hash || null
      });
    } catch (e) {
      console.error("PAGAR PAID -> BINANCE ERROR:", e);

      await sql`
        UPDATE orders SET
          status = 'PAYMENT_CONFIRMED',
          updated_at = NOW()
        WHERE order_id = ${ref}
        AND blockchain_tx_hash IS NULL
      `;

      return res.status(202).json({
        success: true,
        order_id: ref,
        status: "PAYMENT_CONFIRMED",
        message: "Pagamento confirmado; transferência USDT requer processamento."
      });
    }
  }

  if (eventType === "payment.failed" || pStatus === "FAILED") {
    await sql`
      UPDATE orders SET status = 'FAILED', updated_at = NOW()
      WHERE order_id = ${ref}
      AND blockchain_tx_hash IS NULL
    `;

    await sql`
      UPDATE pagar_webhook_events SET processed_at = NOW()
      WHERE event_id = ${eventId}
    `;

    return res.status(200).json({
      success: true,
      order_id: ref,
      status: "FAILED"
    });
  }

  if (pStatus === "CANCELLED") {
    await sql`
      UPDATE orders SET status = 'CANCELLED', updated_at = NOW()
      WHERE order_id = ${ref}
      AND blockchain_tx_hash IS NULL
    `;

    await sql`
      UPDATE pagar_webhook_events SET processed_at = NOW()
      WHERE event_id = ${eventId}
    `;

    return res.status(200).json({
      success: true,
      order_id: ref,
      status: "CANCELLED"
    });
  }

  /*
   * PROCESSING/PENDING do Pagar ficam como PENDING
   * porque são estados permitidos pela nossa tabela.
   */
  await sql`
    UPDATE orders SET status = 'PENDING', updated_at = NOW()
    WHERE order_id = ${ref}
    AND blockchain_tx_hash IS NULL
  `;

  await sql`
    UPDATE pagar_webhook_events SET processed_at = NOW()
    WHERE event_id = ${eventId}
  `;

  return res.status(200).json({
    success: true,
    order_id: ref,
    status: "PENDING"
  });
}

async function createPurchase(req, res, sql) {
  const rawBody = await raw(req);
  const body = json(rawBody);

  const name = text(body.name);
  const phone = text(body.phone);
  const method = payment(
    body.payment || body.payment_method || body.method
  );
  const amount = Number(
    body.amount ?? body.amount_mzn ?? body.valor
  );

  if (!name) return res.status(400).json({ success:false, message:"Nome é obrigatório." });
  if (!phone) return res.status(400).json({ success:false, message:"Telefone é obrigatório." });

  if (!Number.isFinite(amount) || !Number.isInteger(amount)) {
    return res.status(400).json({
      success:false,
      message:"O valor em MZN deve ser um número inteiro."
    });
  }

  if (amount < MIN) {
    return res.status(400).json({
      success:false,
      message:`O valor mínimo é ${MIN} MZN.`
    });
  }

  if (amount > MAX) {
    return res.status(400).json({
      success:false,
      message:`O valor máximo é ${MAX} MZN.`
    });
  }

  if (!METHODS.includes(method)) {
    return res.status(400).json({
      success:false,
      message:"Método de pagamento inválido. Use MPESA ou EMOLA."
    });
  }

  const id = orderId();
  const usdtAmount = usdt(amount);

  let created;

  try {
    created = await sql`
      INSERT INTO orders (
        order_id,name,phone,operation,payment,
        amount,usdt_amount,rate,status,created_at,updated_at
      )
      VALUES (
        ${id},${name},${phone},'BUY_USDT_ADMIN',${method},
        ${amount},${usdtAmount},${RATE},'PENDING',NOW(),NOW()
      )
      RETURNING
        order_id,name,phone,payment,amount,usdt_amount,rate,status,created_at
    `;
  } catch (e) {
    console.error("DATABASE CREATE ORDER ERROR:", e);

    return res.status(500).json({
      success:false,
      message:"Não foi possível criar a ordem no banco de dados."
    });
  }

  try {
    const pagar = await pagarPost(
      "/payments",
      {
        reference: id,
        title: "Compra de USDT",
        description: `Compra de USDT - ${id}`,
        amountMzn: amount,
        method,
        payerPhone: phone
      },
      `payment:${id}`
    );

    const p = extractPayment(pagar);
    const pId = paymentId(pagar);
    const pStatus = paymentStatus(pagar);

    if (!pId) {
      await sql`
        UPDATE orders SET status='FAILED',updated_at=NOW()
        WHERE order_id=${id}
      `;

      return res.status(502).json({
        success:false,
        message:"A Pagar respondeu sem payment_id.",
        order_id:id
      });
    }

    /*
     * Pagar PROCESSING/PENDING = nossa ordem PENDING.
     * Pagar PAID = PAYMENT_CONFIRMED.
     */
    const internalStatus =
      pStatus === "PAID"
        ? "PAYMENT_CONFIRMED"
        : "PENDING";

    await sql`
      UPDATE orders SET
        pagar_payment_id=${pId},
        status=${internalStatus},
        updated_at=NOW()
      WHERE order_id=${id}
    `;

    /*
     * Se a Pagar já retornar PAID, processamos imediatamente.
     */
    if (pStatus === "PAID") {
      try {
        const result = await processPaid(sql, id);

        return res.status(202).json({
          success:true,
          message:"Pagamento confirmado.",
          order:{
            order_id:id,
            amount_mzn:amount,
            usdt_amount:usdtAmount,
            rate:RATE,
            payment:method,
            status:result?.status || "COMPLETED"
          },
          pagar:{
            payment_id:pId,
            status:pStatus,
            data:p
          },
          tx_hash:result?.tx_hash || null
        });
      } catch (e) {
        console.error("PAID -> BINANCE ERROR:", e);

        return res.status(202).json({
          success:true,
          message:"Pagamento confirmado; transferência USDT requer processamento.",
          order:{
            order_id:id,
            amount_mzn:amount,
            usdt_amount:usdtAmount,
            rate:RATE,
            payment:method,
            status:"PAYMENT_CONFIRMED"
          },
          pagar:{
            payment_id:pId,
            status:pStatus
          }
        });
      }
    }

    return res.status(202).json({
      success:true,
      message:"Pagamento enviado para a Pagar. Aguarde a confirmação.",
      order:{
        order_id:id,
        amount_mzn:amount,
        usdt_amount:usdtAmount,
        rate:RATE,
        payment:method,
        status:"PENDING"
      },
      pagar:{
        payment_id:pId,
        status:pStatus || "PROCESSING",
        data:p
      }
    });

  } catch (e) {
    console.error("PAGAR CREATE PAYMENT ERROR:", e);

    /*
     * Se não sabemos se a Pagar recebeu o pedido,
     * mantemos PENDING. Não usamos um status inexistente.
     */
    await sql`
      UPDATE orders SET
        status='PENDING',
        updated_at=NOW()
      WHERE order_id=${id}
      AND blockchain_tx_hash IS NULL
    `;

    return res.status(
      Number(e?.status || 0) >= 400 &&
      Number(e?.status || 0) < 500 ? 502 : 202
    ).json({
      success:false,
      message:
        "A criação do pagamento ficou inconclusiva. A ordem permanece PENDING.",
      order_id:id,
      status:"PENDING",
      detail:errorMessage(e),
      request_id:e?.requestId || null
    });
  }
}

async function statusCheck(req, res, sql) {
  const secret = process.env.PAGAR_SIGNING_SECRET;
  const received = header(req, "x-pagar-secret");

  if (!secret || !received || !compare(received, secret)) {
    return res.status(401).json({
      success:false,
      message:"Não autorizado."
    });
  }

  const id = text(req.query?.order_id || req.query?.orderId);

  if (!id) {
    return res.status(400).json({
      success:false,
      message:"order_id é obrigatório."
    });
  }

  const rows = await sql`
    SELECT order_id,status,pagar_payment_id,blockchain_tx_hash
    FROM orders
    WHERE order_id=${id}
    LIMIT 1
  `;

  if (!rows.length) {
    return res.status(404).json({
      success:false,
      message:"Ordem não encontrada."
    });
  }

  const o = rows[0];

  if (o.blockchain_tx_hash) {
    return res.status(200).json({
      success:true,
      order_id:id,
      status:"COMPLETED",
      tx_hash:o.blockchain_tx_hash
    });
  }

  if (!o.pagar_payment_id) {
    return res.status(409).json({
      success:false,
      message:"A ordem ainda não possui pagar_payment_id."
    });
  }

  const data = await pagarGet(
    `/payments/${encodeURIComponent(o.pagar_payment_id)}`
  );

  const pStatus = paymentStatus(data);

  if (pStatus === "PAID") {
    await sql`
      UPDATE orders SET status='PAYMENT_CONFIRMED',updated_at=NOW()
      WHERE order_id=${id}
      AND blockchain_tx_hash IS NULL
    `;

    try {
      const result = await processPaid(sql, id);

      return res.status(200).json({
        success:true,
        order_id:id,
        status:result?.status || "COMPLETED",
        tx_hash:result?.tx_hash || null
      });
    } catch (e) {
      console.error("STATUS -> BINANCE ERROR:", e);

      return res.status(202).json({
        success:true,
        order_id:id,
        status:"PAYMENT_CONFIRMED",
        message:"Pagamento confirmado; transferência requer processamento."
      });
    }
  }

  const internalStatus =
    pStatus === "FAILED"
      ? "FAILED"
      : pStatus === "CANCELLED"
        ? "CANCELLED"
        : "PENDING";

  await sql`
    UPDATE orders SET status=${internalStatus},updated_at=NOW()
    WHERE order_id=${id}
    AND blockchain_tx_hash IS NULL
  `;

  return res.status(200).json({
    success:true,
    order_id:id,
    payment_status:pStatus || "PENDING",
    status:internalStatus
  });
}

export default async function handler(req, res) {
  try {
    const databaseUrl = db();

    if (!databaseUrl) {
      return res.status(500).json({
        success:false,
        message:"Banco de dados não configurado."
      });
    }

    const sql = neon(databaseUrl);

    if (
      req.method === "POST" &&
      header(req, "pagar-event-id") &&
      header(req, "pagar-signature")
    ) {
      const rawBody = await raw(req);
      return webhook(req, res, sql, rawBody);
    }

    if (
      req.method === "GET" &&
      (req.query?.order_id || req.query?.orderId)
    ) {
      return statusCheck(req, res, sql);
    }

    if (req.method === "POST") {
      return createPurchase(req, res, sql);
    }

    return res.status(405).json({
      success:false,
      message:"Método não permitido."
    });

  } catch (e) {
    console.error("CREATE PURCHASE FATAL ERROR:", e);

    return res.status(500).json({
      success:false,
      message:"Erro interno ao processar a operação.",
      detail:errorMessage(e)
    });
  }
}
