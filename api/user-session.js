import { neon } from "@neondatabase/serverless";
import {
  createHmac,
  timingSafeEqual
} from "node:crypto";

const COOKIE_NAME = "usdtmz_user_session";

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

  const expectedSignature =
    createHmac("sha256", secret)
      .update(data)
      .digest("base64url");

  if (!safeCompare(
    signature,
    expectedSignature
  )) {
    return null;
  }

  try {

    const payload =
      JSON.parse(
        Buffer
          .from(data, "base64url")
          .toString("utf8")
      );

    if (
      !payload.exp ||
      Date.now() > payload.exp
    ) {
      return null;
    }

    if (!payload.id) {
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

  const cookie =
    cookies
      .split(";")
      .map(item => item.trim())
      .find(
        item =>
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

export default async function handler(
  req,
  res
) {

  if (req.method !== "GET") {

    return res.status(405).json({
      success: false,
      message: "Método não permitido."
    });

  }

  const databaseUrl =
    process.env.URL_DO_BANCO_DE_DADOS ||
    process.env.POSTGRES_URL ||
    process.env.DATABASE_URL ||
    process.env.POSTGRES_URL_NON_POOLING ||
    process.env.DATABASE_URL_UNPOOLED;

  const sessionSecret =
    process.env.ADMIN_SESSION_SECRET;

  if (
    !databaseUrl ||
    !sessionSecret
  ) {

    return res.status(500).json({
      success: false,
      message:
        "Configuração do servidor incompleta."
    });

  }

  const token =
    getSessionToken(req);

  const session =
    verifySession(
      token,
      sessionSecret
    );

  if (!session) {

    return res.status(401).json({
      success: false,
      authenticated: false,
      message:
        "Sessão inválida ou expirada."
    });

  }

  try {

    const sql =
      neon(databaseUrl);

    const result =
      await sql`
        SELECT
          u.id,
          u.name,
          u.email,
          u.phone,
          u.status,
          u.created_at,
          COALESCE(
            w.balance,
            0
          ) AS usdt_balance
        FROM users u
        LEFT JOIN wallets w
          ON w.user_id = u.id
          AND w.asset = 'USDT'
        WHERE u.id = ${session.id}
        LIMIT 1
      `;

    if (result.length === 0) {

      return res.status(404).json({
        success: false,
        authenticated: false,
        message:
          "Utilizador não encontrado."
      });

    }

    const user = result[0];

    if (user.status !== "ACTIVE") {

      return res.status(403).json({
        success: false,
        authenticated: false,
        message:
          "Esta conta não está ativa."
      });

    }

    return res.status(200).json({
      success: true,
      authenticated: true,
      user: {
        id: user.id,
        name: user.name,
        email: user.email,
        phone: user.phone,
        status: user.status,
        usdt_balance:
          Number(
            user.usdt_balance || 0
          )
      }
    });

  } catch (error) {

    console.error(
      "Erro ao consultar sessão do utilizador:",
      error
    );

    return res.status(500).json({
      success: false,
      message:
        "Erro ao consultar a sessão."
    });

  }
}
