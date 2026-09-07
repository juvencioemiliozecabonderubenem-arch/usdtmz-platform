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
      Buffer.from(
        data,
        "base64url"
      ).toString("utf8")
    );

    if (
      !payload.exp ||
      Date.now() > Number(payload.exp)
    ) {
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

function getSessionToken(req) {
  const cookies =
    req.headers.cookie || "";

  const cookie = cookies
    .split(";")
    .map((item) => item.trim())
    .find((item) =>
      item.startsWith(
        `${COOKIE_NAME}=`
      )
    );

  if (!cookie) {
    return null;
  }

  return cookie.substring(
    COOKIE_NAME.length + 1
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

function maskAddress(address) {
  const value =
    String(address || "").trim();

  if (!value) {
    return "—";
  }

  if (value.length <= 12) {
    return "TRON TRC-20";
  }

  return (
    value.substring(0, 6) +
    "..." +
    value.substring(
      value.length - 6
    )
  );
}

export default async function handler(
  req,
  res
) {
  /*
   * =====================================================
   * MÉTODO
   * =====================================================
   */

  if (req.method !== "GET") {
    return res.status(405).json({
      success: false,
      message:
        "Método não permitido."
    });
  }

  /*
   * =====================================================
   * CONFIGURAÇÃO
   * =====================================================
   */

  const secret =
    process.env.ADMIN_SESSION_SECRET;

  const databaseUrl =
    getDatabaseUrl();

  if (
    !secret ||
    !databaseUrl
  ) {
    return res.status(500).json({
      success: false,
      message:
        "Configuração do servidor incompleta."
    });
  }

  /*
   * =====================================================
   * ADMIN SESSION
   * =====================================================
   */

  const token =
    getSessionToken(req);

  const session =
    verifySession(
      token,
      secret
    );

  if (!session) {
    return res.status(401).json({
      success: false,
      authenticated: false,
      message:
        "Sessão inválida ou expirada."
    });
  }

  /*
   * =====================================================
   * BANCO
   * =====================================================
   */

  try {
    const sql =
      neon(databaseUrl);

    /*
     * ===================================================
     * 1. RETIRADAS NORMAIS
     * ===================================================
     */

    const normalWithdrawals =
      await sql`
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
     * ===================================================
     * 2. TRANSFERÊNCIAS ADMIN → BINANCE
     * ===================================================
     *
     * Estas operações ficam em "orders".
     *
     * Só mostramos aqui:
     *
     * operation = BUY_USDT_ADMIN
     *
     * Não mostramos o endereço real da Binance.
     */

    const binanceOrders =
      await sql`
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
          blockchain_tx_hash,
          wallet_address,
          pagar_payment_id,
          pagar_event_id,
          created_at,
          updated_at
        FROM orders
        WHERE operation = 'BUY_USDT_ADMIN'
        ORDER BY created_at DESC
      `;

    /*
     * ===================================================
     * CONVERTER RETIRADAS NORMAIS
     * ===================================================
     */

    const normalItems =
      normalWithdrawals.map(
        (item) => ({
          id: item.id,

          withdrawal_id:
            item.withdrawal_id,

          type:
            "WITHDRAWAL",

          source:
            "USER",

          user_id:
            item.user_id,

          order_id:
            item.order_id || null,

          amount:
            item.amount,

          amount_requested:
            item.amount_requested,

          withdrawal_fee:
            item.withdrawal_fee,

          amount_to_send:
            item.amount_to_send,

          asset:
            item.asset,

          network:
            item.network,

          /*
           * Retirada normal:
           * mostramos o destino mascarado.
           */

          destination_address:
            maskAddress(
              item.destination_address
            ),

          destination_label:
            "Carteira TRON",

          status:
            item.status,

          tx_hash:
            item.tx_hash || null,

          created_at:
            item.created_at,

          updated_at:
            item.updated_at,

          /*
           * Campo útil para o frontend.
           */

          is_binance:
            false
        })
      );

    /*
     * ===================================================
     * CONVERTER BINANCE
     * ===================================================
     */

    const binanceItems =
      binanceOrders.map(
        (order) => ({
          /*
           * ID visual separado da retirada normal.
           */

          id:
            `BINANCE-${order.id}`,

          withdrawal_id:
            `BINANCE-${order.order_id}`,

          type:
            "BINANCE_TRANSFER",

          source:
            "ADMIN_PURCHASE",

          user_id:
            null,

          order_id:
            order.order_id,

          /*
           * Para compatibilidade com o
           * frontend que espera "amount".
           */

          amount:
            order.usdt_amount,

          amount_requested:
            order.usdt_amount,

          withdrawal_fee:
            0,

          amount_to_send:
            order.usdt_amount,

          asset:
            "USDT",

          network:
            "TRON",

          /*
           * NÃO devolvemos o endereço real
           * da Binance.
           */

          destination_address:
            "BINANCE TRC-20",

          destination_label:
            "Binance / TRON TRC-20",

          status:
            order.status,

          tx_hash:
            order.blockchain_tx_hash ||
            null,

          created_at:
            order.created_at,

          updated_at:
            order.updated_at,

          is_binance:
            true,

          /*
           * Informações adicionais
           * úteis para o Admin.
           */

          payment:
            order.payment,

          payment_amount_mzn:
            order.amount,

          rate:
            order.rate,

          pagar_payment_id:
            order.pagar_payment_id ||
            null,

          pagar_event_id:
            order.pagar_event_id ||
            null
        })
      );

    /*
     * ===================================================
     * JUNTAR E ORDENAR
     * ===================================================
     */

    const withdrawals = [
      ...normalItems,
      ...binanceItems
    ].sort((a, b) => {
      const dateA =
        a.created_at
          ? new Date(a.created_at).getTime()
          : 0;

      const dateB =
        b.created_at
          ? new Date(b.created_at).getTime()
          : 0;

      return dateB - dateA;
    });

    /*
     * ===================================================
     * RESPOSTA
     * ===================================================
     */

    return res.status(200).json({
      success: true,

      withdrawals,

      /*
       * Também devolvemos separadamente,
       * caso o Admin queira usar no futuro.
       */

      normal_withdrawals:
        normalItems,

      binance_transfers:
        binanceItems,

      counts: {
        total:
          withdrawals.length,

        normal:
          normalItems.length,

        binance:
          binanceItems.length
      }
    });
  } catch (error) {
    console.error(
      "Erro ao consultar levantamentos:",
      error
    );

    return res.status(500).json({
      success: false,
      message:
        "Erro ao consultar os levantamentos.",
      detail:
        error?.message ||
        "Erro desconhecido."
    });
  }
}
