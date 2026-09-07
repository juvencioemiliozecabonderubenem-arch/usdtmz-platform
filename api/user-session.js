import { createHmac, timingSafeEqual } from "node:crypto";

const COOKIE_NAME = "usdtmz_user_session";

function json(res, status, body) {
  return res.status(status).json(body);
}

function safeCompare(a, b) {
  const A = Buffer.from(String(a));
  const B = Buffer.from(String(b));

  if (A.length !== B.length) {
    return false;
  }

  return timingSafeEqual(A, B);
}

function getCookie(req, name) {
  const cookies = req.headers.cookie || "";

  const cookie = cookies
    .split(";")
    .map((item) => item.trim())
    .find((item) => item.startsWith(`${name}=`));

  if (!cookie) {
    return null;
  }

  return decodeURIComponent(
    cookie.substring(name.length + 1)
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

  const expected = createHmac(
    "sha256",
    secret
  )
    .update(data)
    .digest("base64url");

  if (!safeCompare(signature, expected)) {
    return null;
  }

  try {
    const payload = JSON.parse(
      Buffer.from(
        data,
        "base64url"
      ).toString("utf8")
    );

    if (!payload || !payload.exp) {
      return null;
    }

    if (
      Date.now() >=
      Number(payload.exp)
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

export default async function handler(
  req,
  res
) {
  if (req.method !== "GET") {
    return json(res, 405, {
      success: false,
      message:
        "Método não permitido."
    });
  }

  const secret =
    process.env.USER_SESSION_SECRET;

  if (!secret) {
    console.error(
      "USER_SESSION_SECRET não configurado."
    );

    return json(res, 500, {
      success: false,
      message:
        "Sessão do usuário não está configurada."
    });
  }

  const token = getCookie(
    req,
    COOKIE_NAME
  );

  const session =
    verifySession(
      token,
      secret
    );

  if (!session) {
    return json(res, 401, {
      success: false,
      authenticated: false,
      message:
        "Sessão inválida ou expirada."
    });
  }

  return json(res, 200, {
    success: true,
    authenticated: true,

    user: {
      id: session.id,
      name: session.name || null,
      phone: session.phone || null,
      email: session.email || null
    },

    expires_at:
      new Date(
        Number(session.exp)
      ).toISOString()
  });
}
