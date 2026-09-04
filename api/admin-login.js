import { createHmac, timingSafeEqual } from "node:crypto";

const COOKIE_NAME = "usdtmz_admin_session";
const SESSION_HOURS = 12;

function safeCompare(a, b) {
  const A = Buffer.from(String(a));
  const B = Buffer.from(String(b));

  if (A.length !== B.length) return false;

  return timingSafeEqual(A, B);
}

function createSession(email, secret) {
  const payload = {
    id: "admin",
    email,
    exp: Date.now() + SESSION_HOURS * 60 * 60 * 1000
  };

  const data = Buffer.from(JSON.stringify(payload)).toString("base64url");

  const signature = createHmac("sha256", secret)
    .update(data)
    .digest("base64url");

  return `${data}.${signature}`;
}

export default function handler(req, res) {
  if (req.method !== "POST") {
    return res.status(405).json({
      success: false,
      message: "Método não permitido."
    });
  }

  const {
    ADMIN_EMAIL,
    ADMIN_PASSWORD,
    ADMIN_SESSION_SECRET
  } = process.env;

  if (!ADMIN_EMAIL || !ADMIN_PASSWORD || !ADMIN_SESSION_SECRET) {
    return res.status(500).json({
      success: false,
      message: "Configuração do servidor incompleta."
    });
  }

  const { email, password } = req.body || {};

  if (!email || !password) {
    return res.status(400).json({
      success: false,
      message: "Email e senha são obrigatórios."
    });
  }

  if (
    !safeCompare(email.trim().toLowerCase(), ADMIN_EMAIL.trim().toLowerCase()) ||
    !safeCompare(password, ADMIN_PASSWORD)
  ) {
    return res.status(401).json({
      success: false,
      message: "Email ou senha incorretos."
    });
  }

  const session = createSession(
    ADMIN_EMAIL.trim().toLowerCase(),
    ADMIN_SESSION_SECRET
  );

  res.setHeader(
    "Set-Cookie",
    `${COOKIE_NAME}=${session}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=43200`
  );

  return res.status(200).json({
    success: true,
    message: "Login realizado com sucesso."
  });
}
