import { neon } from "@neondatabase/serverless";
import { createHmac, timingSafeEqual } from "node:crypto";

const COOKIE_NAME = "usdtmz_admin_session";

function safeCompare(a, b) {
  const A = Buffer.from(String(a));
  const B = Buffer.from(String(b));

  if (A.length !== B.length) {
    return false;
  }

  return timingSafeEqual(A, B);
}

function getSessionToken(req) {
  const cookies = req.headers.cookie || "";

  const cookie = cookies
    .split(";")
    .map((item) => item.trim())
    .find((item) =>
      item.startsWith(`${COOKIE_NAME}=`)
    );

  if (!cookie) {
    return null;
  }

  return cookie.substring(COOKIE_NAME.length + 1);
}

function verifySession(token, secret) {
  if (!token || !secret) {
    return null;
  }

  const parts = token.split(".");

  if (parts.length !== 2) {
    return null;
  }

  const [data, signature] = parts;

  const expectedSignature = createHmac(
    "sha256",
    secret
  )
    .update(data)
    .digest("base64url");

  if (!safeCompare(signature, expectedSignature)) {
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

function getDatabaseUrl() {
  return (
    process.env.URL_DO_BANCO_DE_DADOS ||
    process.env.POSTGRES_URL ||
    process.env.DATABASE_URL ||
    process.env.POSTGRES_URL_NON_POOLING ||
    process.env.DATABASE_URL_UNPOOLED
  );
}

function normalizeStatus(value) {
  return String(value || "")
    .trim()
    .toUpperCase();
}

export default async function handler(req, res) {
  if (req.method !== "GET") {
    return res.status(405).json({
      success: false,
      message: "Método não permitido."
    });
  }

  const secret = process.env.ADMIN_SESSION_SECRET;
  const databaseUrl = getDatabaseUrl();

  if (!secret || !databaseUrl) {
    return res.status(500).json({
      success: false,
      message: "Configuração do servidor incompleta."
    });
  }

  const token = getSessionToken(req);
  const session = verifySession(token, secret);

  if (!session) {
    return res.status(401).json({
      success: false,
      authenticated: false,
      message: "Sessão inválida ou expirada."
    });
  }

  try {
    const sql = neon(databaseUrl);

    /*
     * =====================================================
     * RETIRADAS NORMAIS
     * =====================================================
     */
    const withdrawals = await sql`
      SELECT
        id,
        withdrawal_id,
        user_id,
        amount,
        asset,
        network,
        destination_address,
        status,
        tx_hash,
        created_at,
        updated_at,
        order_id,
        amount_requested,
        withdrawal_fee,
        amount_to_send
      FROM withdrawals
      ORDER BY created_at DESC
    `;

    /*
     * =====================================================
     * COMPRAS ADMIN → BINANCE
     *
     * Não enviamos o endereço real da Binance
     * para o frontend.
     * =====================================================
     */
    const binanceOrders = await sql`
      SELECT
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
        created_at,
        updated_at,
        mpesa_transaction_id,
        emola_transaction_id,
        pagar_payment_id,
        pagar_event_id,
        blockchain_tx_hash
      FROM orders
      WHERE operation = 'BUY_USDT_ADMIN'
      ORDER BY created_at DESC
    `;

    /*
     * =====================================================
     * NORMALIZAÇÃO DAS RETIRADAS
     * =====================================================
     */
    const normalRows = withdrawals.map((item) => ({
      id: item.id,
      withdrawal_id: item.withdrawal_id,
      user_id: item.user_id,
      type: "WITHDRAWAL",
      source: "USER_WITHDRAWAL",

      amount: item.amount,
      amount_requested:
        item.amount_requested ?? item.amount,
      amount_to_send:
        item.amount_to_send ?? item.amount,
      withdrawal_fee:
        item.withdrawal_fee ?? null,

      asset: item.asset || "USDT",
      network: item.network || "TRON",

      destination_address:
        item.destination_address || null,

      destination_label: null,

      status: normalizeStatus(item.status),

      tx_hash:
        item.tx_hash || null,

      created_at: item.created_at,
      updated_at: item.updated_at,

      order_id:
        item.order_id || null,

      is_binance: false,

      payment: null,
      payment_amount: null,
      usdt_amount: null,
      rate: null,

      name: null,
      phone: null,

      mpesa_transaction_id: null,
      emola_transaction_id: null,

      pagar_payment_id: null,
      pagar_event_id: null
    }));

    /*
     * =====================================================
     * NORMALIZAÇÃO DAS TRANSFERÊNCIAS BINANCE
     * =====================================================
     */
    const binanceRows = binanceOrders.map((order) => ({
      id: `binance_${order.id}`,

      withdrawal_id: null,
      user_id: null,

      type: "BINANCE_TRANSFER",
      source: "ADMIN_PURCHASE",

      amount: order.usdt_amount,
      amount_requested: order.usdt_amount,
      amount_to_send: order.usdt_amount,
      withdrawal_fee: 0,

      asset: "USDT",
      network: "TRON",

      /*
       * Nunca enviar o endereço real da Binance
       * para o navegador.
       */
      destination_address: "BINANCE TRC-20",
      destination_label: "Binance / TRON TRC-20",

      status: normalizeStatus(order.status),

      tx_hash:
        order.blockchain_tx_hash || null,

      created_at: order.created_at,
      updated_at: order.updated_at,

      order_id: order.order_id,

      is_binance: true,

      payment: order.payment || null,
      payment_amount: order.amount || null,
      usdt_amount: order.usdt_amount || null,
      rate: order.rate || null,

      name: order.name || null,
      phone: order.phone || null,

      mpesa_transaction_id:
        order.mpesa_transaction_id || null,

      emola_transaction_id:
        order.emola_transaction_id || null,

      pagar_payment_id:
        order.pagar_payment_id || null,

      pagar_event_id:
        order.pagar_event_id || null
    }));

    /*
     * =====================================================
     * JUNTAR AS DUAS LISTAS
     * =====================================================
     */
    const allRows = [
      ...normalRows,
      ...binanceRows
    ];

    /*
     * Mais recentes primeiro.
     */
    allRows.sort((a, b) => {
      const dateA = new Date(a.created_at || 0).getTime();
      const dateB = new Date(b.created_at || 0).getTime();

      return dateB - dateA;
    });

    /*
     * =====================================================
     * ESTATÍSTICAS
     * =====================================================
     */
    const binanceCompleted =
      binanceRows.filter(
        (item) =>
          item.status === "COMPLETED"
      ).length;

    const binanceProcessing =
      binanceRows.filter(
        (item) =>
          item.status === "PROCESSING"
      ).length;

    const binanceFailed =
      binanceRows.filter(
        (item) =>
          item.status === "FAILED"
      ).length;

    return res.status(200).json({
      success: true,
      authenticated: true,

      withdrawals: allRows,

      /*
       * Mantidos separados para o frontend
       * poder usar qualquer uma das listas.
       */
      normal_withdrawals: normalRows,

      binance_transfers: binanceRows,

      counts: {
        total: allRows.length,
        withdrawals: normalRows.length,
        binance_transfers: binanceRows.length,

        binance_completed:
          binanceCompleted,

        binance_processing:
          binanceProcessing,

        binance_failed:
          binanceFailed
      }
    });
  } catch (error) {
    console.error(
      "ADMIN WITHDRAWALS ERROR:",
      error
    );

    return res.status(500).json({
      success: false,
      message: "Erro ao consultar retiradas.",
      detail:
        error?.message ||
        "Erro desconhecido."
    });
  }
}
