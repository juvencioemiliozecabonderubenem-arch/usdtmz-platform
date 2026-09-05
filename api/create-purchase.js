import { neon } from "@neondatabase/serverless";
import {
  createHmac,
  timingSafeEqual,
  randomBytes
} from "node:crypto";

const COOKIE_NAME = "usdtmz_user_session";
const RATE = 65;

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

  if (!safeCompare(signature, expectedSignature)) {
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

function generatePurchaseReference() {
  const random =
    randomBytes(5)
      .toString("hex")
      .toUpperCase();

  return `USDTMZ-${Date.now()}-${random}`;
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

  const {
    amount_mzn,
    payment_method
  } = req.body || {};

  const mzn =
    Number(amount_mzn);

  if (
    !Number.isFinite(mzn) ||
    mzn < 10
  ) {
    return res.status(400).json({
      success: false,
      message:
        "O valor mínimo é 10 MZN."
    });
  }

  if (
    payment_method !== "mpesa" &&
    payment_method !== "emola"
  ) {
    return res.status(400).json({
      success: false,
      message:
        "Método de pagamento inválido."
    });
  }

  const amountUsdt =
    Number(
      (mzn / RATE).toFixed(4)
    );

  const paymentMethod =
    payment_method === "mpesa"
      ? "M-Pesa"
      : "e-Mola";

  const purchaseReference =
    generatePurchaseReference();

  try {

    const sql =
      neon(databaseUrl);

    const userResult =
      await sql`
        SELECT
          id,
          name,
          phone,
          status
        FROM users
        WHERE id = ${session.id}
        LIMIT 1
      `;

    if (userResult.length === 0) {
      return res.status(404).json({
        success: false,
        message:
          "Utilizador não encontrado."
      });
    }

    const user =
      userResult[0];

    if (user.status !== "ACTIVE") {
      return res.status(403).json({
        success: false,
        message:
          "Esta conta não está ativa."
      });
    }

    const result =
      await sql`
        INSERT INTO purchases (
          user_id,
          amount_mzn,
          amount_usdt,
          payment_method,
          status,
          payment_reference
        )
        VALUES (
          ${user.id},
          ${mzn},
          ${amountUsdt},
          ${paymentMethod},
          'PENDENTE',
          ${purchaseReference}
        )
        RETURNING
          id,
          user_id,
          amount_mzn,
          amount_usdt,
          payment_method,
          status,
          payment_reference,
          created_at
      `;

    const purchase =
      result[0];

    return res.status(201).json({
      success: true,
      message:
        "Ordem de compra criada com sucesso.",
      purchase
    });

  } catch (error) {

    console.error(
      "Erro ao criar compra:",
      error
    );

    return res.status(500).json({
      success: false,
      message:
        "Erro ao criar a ordem de compra."
    });
  }
}
