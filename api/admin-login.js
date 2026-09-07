import { createHmac, timingSafeEqual } from "node:crypto";

const COOKIE_NAME = "usdtmz_admin_session";
const SESSION_HOURS = 12;

function safeCompare(a, b) {
  const A = Buffer.from(String(a));
  const B = Buffer.from(String(b));

  if (A.length !== B.length) {
    return false;
  }

  return timingSafeEqual(A, B);
}

function createSession(email, secret) {
  const payload = {
    id: "admin",
    email,
    exp:
      Date.now() +
      SESSION_HOURS * 60 * 60 * 1000
  };

  const data = Buffer.from(
    JSON.stringify(payload)
  ).toString("base64url");

  const signature = createHmac(
    "sha256",
    secret
  )
    .update(data)
    .digest("base64url");

  return `${data}.${signature}`;
}

export default function handler(req, res) {
  /*
   * =====================================================
   * SOMENTE POST
   * =====================================================
   */

  if (req.method !== "POST") {
    return res.status(405).json({
      success: false,
      message: "Método não permitido."
    });
  }

  /*
   * =====================================================
   * CONFIGURAÇÕES SECRETAS
   * =====================================================
   *
   * Nunca colocar esses valores diretamente
   * neste arquivo.
   */

  const {
    ADMIN_EMAIL,
    ADMIN_PASSWORD,
    ADMIN_SESSION_SECRET
  } = process.env;

  if (
    !ADMIN_EMAIL ||
    !ADMIN_PASSWORD ||
    !ADMIN_SESSION_SECRET
  ) {
    return res.status(500).json({
      success: false,
      message:
        "Configuração do servidor incompleta."
    });
  }

  /*
   * =====================================================
   * DADOS DO LOGIN
   * =====================================================
   */

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

  /*
   * =====================================================
   * VERIFICAÇÃO
   * =====================================================
   */

  const validEmail = safeCompare(
    String(email)
      .trim()
      .toLowerCase(),

    String(ADMIN_EMAIL)
      .trim()
      .toLowerCase()
  );

  const validPassword = safeCompare(
    String(password),
    String(ADMIN_PASSWORD)
  );

  if (!validEmail || !validPassword) {
    return res.status(401).json({
      success: false,
      message:
        "Email ou senha incorretos."
    });
  }

  /*
   * =====================================================
   * CRIAR SESSÃO
   * =====================================================
   */

  const session = createSession(
    String(ADMIN_EMAIL)
      .trim()
      .toLowerCase(),

    ADMIN_SESSION_SECRET
  );

  /*
   * =====================================================
   * COOKIE SEGURO
   * =====================================================
   */

  res.setHeader(
    "Set-Cookie",
    `${COOKIE_NAME}=${session}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=43200`
  );

  /*
   * =====================================================
   * SUCESSO
   * =====================================================
   */

  return res.status(200).json({
    success: true,
    message:
      "Login realizado com sucesso."
  });
}
