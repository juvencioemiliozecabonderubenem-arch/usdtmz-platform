import { neon } from "@neondatabase/serverless";
import {
  createHmac,
  timingSafeEqual,
  scryptSync
} from "node:crypto";

const COOKIE_NAME = "usdtmz_user_session";
const SESSION_HOURS = 12;

function safeCompare(a, b) {
  const A = Buffer.from(String(a));
  const B = Buffer.from(String(b));

  if (A.length !== B.length) {
    return false;
  }

  return timingSafeEqual(A, B);
}

function verifyPassword(password, storedHash) {
  if (!storedHash || !storedHash.includes(":")) {
    return false;
  }

  const [salt, originalHash] =
    storedHash.split(":");

  if (!salt || !originalHash) {
    return false;
  }

  const calculatedHash =
    scryptSync(
      password,
      salt,
      64
    ).toString("hex");

  return safeCompare(
    calculatedHash,
    originalHash
  );
}

function createSession(user, secret) {

  const payload = {
    id: String(user.id),
    email: user.email,
    exp:
      Date.now() +
      SESSION_HOURS *
      60 *
      60 *
      1000
  };

  const data =
    Buffer
      .from(JSON.stringify(payload))
      .toString("base64url");

  const signature =
    createHmac(
      "sha256",
      secret
    )
      .update(data)
      .digest("base64url");

  return `${data}.${signature}`;
}

export default async function handler(req, res) {

  if (req.method !== "POST") {
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

  if (!databaseUrl || !sessionSecret) {
    return res.status(500).json({
      success: false,
      message:
        "Configuração do servidor incompleta."
    });
  }

  const {
    email,
    password
  } = req.body || {};

  if (!email || !password) {
    return res.status(400).json({
      success: false,
      message:
        "Email e senha são obrigatórios."
    });
  }

  try {

    const sql =
      neon(databaseUrl);

    const normalizedEmail =
      email
        .trim()
        .toLowerCase();

    const result =
      await sql`
        SELECT
          id,
          name,
          email,
          phone,
          password_hash,
          status
        FROM users
        WHERE email = ${normalizedEmail}
        LIMIT 1
      `;

    if (result.length === 0) {
      return res.status(401).json({
        success: false,
        message:
          "Email ou senha incorretos."
      });
    }

    const user = result[0];

    if (user.status !== "ACTIVE") {
      return res.status(403).json({
        success: false,
        message:
          "Esta conta não está ativa."
      });
    }

    const passwordValid =
      verifyPassword(
        password,
        user.password_hash
      );

    if (!passwordValid) {
      return res.status(401).json({
        success: false,
        message:
          "Email ou senha incorretos."
      });
    }

    const session =
      createSession(
        user,
        sessionSecret
      );

    res.setHeader(
      "Set-Cookie",
      `${COOKIE_NAME}=${session}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=43200`
    );

    return res.status(200).json({
      success: true,
      message:
        "Login realizado com sucesso.",
      user: {
        id: user.id,
        name: user.name,
        email: user.email,
        phone: user.phone,
        status: user.status
      }
    });

  } catch (error) {

    console.error(
      "Erro no login do utilizador:",
      error
    );

    return res.status(500).json({
      success: false,
      message:
        "Erro ao realizar login."
    });
  }
}
