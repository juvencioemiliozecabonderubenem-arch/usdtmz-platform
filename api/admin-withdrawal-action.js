import { neon } from "@neondatabase/serverless";
import { createHmac, timingSafeEqual } from "node:crypto";

const COOKIE_NAME = "usdtmz_admin_session";

/**
 * Compara duas strings de forma segura.
 */
function safeCompare(a, b) {
  const A = Buffer.from(String(a));
  const B = Buffer.from(String(b));

  if (A.length !== B.length) {
    return false;
  }

  return timingSafeEqual(A, B);
}

/**
 * Obtém o token da sessão do administrador.
 */
function getSessionToken(req) {
  const cookies = req.headers.cookie || "";

  const cookie = cookies
    .split(";")
    .map((item) => item.trim())
    .find((item) => item.startsWith(`${COOKIE_NAME}=`));

  if (!cookie) {
    return null;
  }

  return cookie.substring(COOKIE_NAME.length + 1);
}

/**
 * Valida a sessão assinada do administrador.
 */
function verifySession(token, secret) {
  if (!token || !secret) {
    return null;
  }

  const parts = token.split(".");

  if (parts.length !== 2) {
    return null;
  }

  const [data, signature] = parts;

  const expectedSignature = createHmac("sha256", secret)
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

/**
 * Obtém a URL do banco.
 */
function getDatabaseUrl() {
  return (
    process.env.URL_DO_BANCO_DE_DADOS ||
    process.env.POSTGRES_URL ||
    process.env.DATABASE_URL ||
    process.env.POSTGRES_URL_NON_POOLING ||
    process.env.DATABASE_URL_UNPOOLED
  );
}

export default async function handler(req, res) {
  /**
   * Esta API aceita somente POST.
   */
  if (req.method !== "POST") {
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

  /**
   * Verifica sessão do administrador.
   */
  const token = getSessionToken(req);
  const session = verifySession(token, secret);

  if (!session) {
    return res.status(401).json({
      success: false,
      authenticated: false,
      message: "Sessão inválida ou expirada."
    });
  }

  /**
   * Dados recebidos.
   */
  const {
    withdrawal_id,
    action,
    rejection_reason
  } = req.body || {};

  if (!withdrawal_id) {
    return res.status(400).json({
      success: false,
      message: "withdrawal_id é obrigatório."
    });
  }

  if (!action) {
    return res.status(400).json({
      success: false,
      message: "A ação é obrigatória."
    });
  }

  const normalizedAction = String(action)
    .trim()
    .toUpperCase();

  /**
   * Ações permitidas:
   * AUTHORIZE = autorizar levantamento
   * REJECT    = rejeitar levantamento
   */
  if (
    normalizedAction !== "AUTHORIZE" &&
    normalizedAction !== "REJECT"
  ) {
    return res.status(400).json({
      success: false,
      message: "Ação inválida."
    });
  }

  /**
   * Rejeição precisa obrigatoriamente de motivo.
   */
  if (
    normalizedAction === "REJECT" &&
    (!rejection_reason ||
      String(rejection_reason).trim().length < 3)
  ) {
    return res.status(400).json({
      success: false,
      message: "Informe o motivo da rejeição."
    });
  }

  try {
    const sql = neon(databaseUrl);

    /**
     * Procura o levantamento.
     */
    const current = await sql`
      SELECT
        id,
        withdrawal_id,
        user_id,
        status,
        amount,
        asset,
        network,
        destination_address,
        tx_hash,
        created_at,
        updated_at,
        order_id
      FROM withdrawals
      WHERE withdrawal_id = ${String(withdrawal_id)}
      LIMIT 1
    `;

    if (current.length === 0) {
      return res.status(404).json({
        success: false,
        message: "Levantamento não encontrado."
      });
    }

    const withdrawal = current[0];

    const currentStatus = String(
      withdrawal.status || ""
    )
      .trim()
      .toUpperCase();

    /**
     * Somente levantamentos pendentes
     * podem ser autorizados ou rejeitados.
     */
    if (
      currentStatus !== "PENDING" &&
      currentStatus !== "PENDENTE"
    ) {
      return res.status(409).json({
        success: false,
        message:
          `Este levantamento não está pendente. Estado atual: ${withdrawal.status}.`
      });
    }

    let newStatus;
    let reason = null;

    if (normalizedAction === "AUTHORIZE") {
      newStatus = "AUTHORIZED";
    } else {
      newStatus = "REJECTED";
      reason = String(rejection_reason).trim();
    }

    /**
     * Atualização atômica.
     *
     * A condição WHERE garante que outro pedido
     * não consiga autorizar/rejeitar simultaneamente
     * o mesmo levantamento.
     */
    const updated = await sql`
      UPDATE withdrawals
      SET
        status = ${newStatus},
        updated_at = NOW()
      WHERE withdrawal_id = ${String(withdrawal_id)}
        AND (
          UPPER(status) = 'PENDING'
          OR UPPER(status) = 'PENDENTE'
        )
      RETURNING
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
        order_id
    `;

    /**
     * Se nenhuma linha foi atualizada,
     * outra operação provavelmente alterou o levantamento.
     */
    if (updated.length === 0) {
      return res.status(409).json({
        success: false,
        message:
          "O levantamento já foi alterado por outra operação."
      });
    }

    return res.status(200).json({
      success: true,
      authenticated: true,
      message:
        newStatus === "AUTHORIZED"
          ? "Levantamento autorizado com sucesso."
          : "Levantamento rejeitado com sucesso.",
      withdrawal: updated[0],
      rejection_reason: reason
    });
  } catch (error) {
    console.error(
      "ADMIN WITHDRAWAL ACTION ERROR:",
      error
    );

    return res.status(500).json({
      success: false,
      message: "Erro ao processar o levantamento.",
      detail: error?.message || "Erro desconhecido."
    });
  }
}
