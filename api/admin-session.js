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

    if (!payload || payload.id !== "admin") {
      return null;
    }

    if (!payload.email) {
      return null;
    }

    if (!payload.exp) {
      return null;
    }

    const expiresAt = Number(payload.exp);

    if (!Number.isFinite(expiresAt)) {
      return null;
    }

    if (Date.now() >= expiresAt) {
      return null;
    }

    return payload;
  } catch {
    return null;
  }
}

export default function handler(req, res) {
  /*
   * =====================================================
   * SOMENTE GET
   * =====================================================
   */

  if (req.method !== "GET") {
    return res.status(405).json({
      success: false,
      authenticated: false,
      message: "Método não permitido."
    });
  }

  /*
   * =====================================================
   * SECRET DA SESSÃO
   * =====================================================
   */

  const secret =
    process.env.ADMIN_SESSION_SECRET;

  if (!secret) {
    return res.status(500).json({
      success: false,
      authenticated: false,
      message:
        "ADMIN_SESSION_SECRET não configurado."
    });
  }

  /*
   * =====================================================
   * OBTER COOKIE
   * =====================================================
   */

  const token = getSessionToken(req);

  if (!token) {
    return res.status(401).json({
      success: false,
      authenticated: false,
      message: "Sessão Admin não encontrada."
    });
  }

  /*
   * =====================================================
   * VALIDAR SESSÃO
   * =====================================================
   */

  const session = verifySession(
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
   * SESSÃO VÁLIDA
   * =====================================================
   */

  return res.status(200).json({
    success: true,
    authenticated: true,

    admin: {
      id: "admin",
      email: session.email
    },

    expires_at:
      new Date(
        Number(session.exp)
      ).toISOString()
  });
}
