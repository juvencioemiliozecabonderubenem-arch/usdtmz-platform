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

  return cookie.substring(
    COOKIE_NAME.length + 1
  );
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

    if (!payload.exp) {
      return null;
    }

    if (Date.now() > Number(payload.exp)) {
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

export default async function handler(req, res) {
  /*
   * =====================================================
   * MÉTODO
   * =====================================================
   */

  if (req.method !== "GET") {
    return res.status(405).json({
      success: false,
      message: "Método não permitido."
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

  if (!secret) {
    return res.status(500).json({
      success: false,
      authenticated: false,
      message:
        "ADMIN_SESSION_SECRET não configurado."
    });
  }

  if (!databaseUrl) {
    return res.status(500).json({
      success: false,
      message:
        "URL do banco de dados não configurada."
    });
  }

  /*
   * =====================================================
   * VERIFICAR ADMIN
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
        "Sessão Admin inválida ou expirada."
    });
  }

  /*
   * =====================================================
   * CONSULTAR USUÁRIOS
   * =====================================================
   */

  try {
    const sql =
      neon(databaseUrl);

    const users =
      await sql`
        SELECT
          id,
          name,
          phone,
          email,
          created_at
        FROM users
        ORDER BY created_at DESC
      `;

    /*
     * ===================================================
     * RESPOSTA
     * ===================================================
     */

    return res.status(200).json({
      success: true,
      authenticated: true,
      users,
      count: users.length
    });
  } catch (error) {
    console.error(
      "ADMIN USERS ERROR:",
      error
    );

    return res.status(500).json({
      success: false,
      message:
        "Erro ao consultar usuários.",
      detail:
        error?.message ||
        "Erro desconhecido."
    });
  }
}
