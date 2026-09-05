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

  const databaseUrl =
    process.env.URL_DO_BANCO_DE_DADOS ||
    process.env.POSTGRES_URL ||
    process.env.DATABASE_URL ||
    process.env.POSTGRES_URL_NON_POOLING ||
    process.env.DATABASE_URL_UNPOOLED;

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
