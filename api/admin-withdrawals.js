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

    if (!payload.exp || Date.now() > payload.exp) {
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
  const cookies = req.headers.cookie || "";

  const cookie = cookies
    .split(";")
    .map(item => item.trim())
    .find(item => item.startsWith(`${COOKIE_NAME}=`));

  if (!cookie) {
    return null;
  }

  return cookie.substring(COOKIE_NAME.length + 1);
}

export default async function handler(req, res) {
  if (req.method !== "GET") {
    return res.status(405).json({
      success: false,
      message: "Método não permitido."
    });
  }

  const secret = process.env.ADMIN_SESSION_SECRET;

  // Aceita a variável que criamos e também variáveis padrão
  // que podem ter sido criadas pela integração Neon/Vercel.
  const databaseUrl =
    process.env.URL_DO_BANCO_DE_DADOS ||
    process.env.POSTGRES_URL ||
    process.env.DATABASE_URL ||
    process.env.POSTGRES_URL_NON_POOLING ||
    process.env.DATABASE_URL_UNPOOLED;

  if (!secret) {
    return res.status(500).json({
      success: false,
      message: "Configuração do administrador incompleta."
    });
  }

  if (!databaseUrl) {
    return res.status(500).json({
      success: false,
      message: "Configuração do banco de dados incompleta."
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

    const withdrawals = await sql`
      SELECT
        w.id,
        w.user_id,
        w.amount_usdt,
        w.wallet_address,
        w.network,
        w.status,
        w.transaction_hash,
        w.rejection_reason,
        w.created_at,
        w.authorized_at,
        w.processed_at,
        w.completed_at,
        w.updated_at
      FROM withdrawals AS w
      ORDER BY w.created_at DESC
    `;

    return res.status(200).json({
      success: true,
      withdrawals
    });

  } catch (error) {
    console.error("Erro ao consultar levantamentos:", error);

    return res.status(500).json({
      success: false,
      message: "Erro ao consultar os levantamentos."
    });
  }
}
