import { createHmac, timingSafeEqual } from "node:crypto";
import { TronWeb } from "tronweb";

const COOKIE_NAME = "usdtmz_admin_session";
const USDT_CONTRACT =
  "TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t";

function json(res, status, body) {
  return res.status(status).json(body);
}

function safeCompare(a, b) {
  const first = Buffer.from(String(a));
  const second = Buffer.from(String(b));

  if (first.length !== second.length) {
    return false;
  }

  return timingSafeEqual(first, second);
}

function getCookie(req, name) {
  const header = req.headers.cookie || "";

  for (const part of header.split(";")) {
    const item = part.trim();

    if (item.startsWith(`${name}=`)) {
      return decodeURIComponent(
        item.substring(name.length + 1)
      );
    }
  }

  return null;
}

function verifyAdminSession(req) {
  const token = getCookie(
    req,
    COOKIE_NAME
  );

  const secret =
    process.env.ADMIN_SESSION_SECRET;

  if (!token || !secret) {
    return false;
  }

  const parts = token.split(".");

  if (parts.length !== 2) {
    return false;
  }

  const data = parts[0];
  const signature = parts[1];

  const expected = createHmac(
    "sha256",
    secret
  )
    .update(data)
    .digest("base64url");

  if (
    !safeCompare(
      signature,
      expected
    )
  ) {
    return false;
  }

  try {
    const payload = JSON.parse(
      Buffer.from(
        data,
        "base64url"
      ).toString("utf8")
    );

    if (
      !payload ||
      payload.id !== "admin"
    ) {
      return false;
    }

    if (
      !payload.exp ||
      Date.now() >= Number(payload.exp)
    ) {
      return false;
    }

    return true;
  } catch {
    return false;
  }
}

export default async function handler(
  req,
  res
) {
  /* =====================================================
     SOMENTE GET
     ===================================================== */

  if (req.method !== "GET") {
    return json(res, 405, {
      success: false,
      message: "Método não permitido."
    });
  }

  /* =====================================================
     VERIFICAR ADMIN
     ===================================================== */

  if (!verifyAdminSession(req)) {
    return json(res, 401, {
      success: false,
      authenticated: false,
      message:
        "Não autorizado."
    });
  }

  /* =====================================================
     CARTEIRA
     ===================================================== */

  const walletAddress =
    String(
      process.env
        .USDTMZ_TRON_WALLET_ADDRESS ||
        ""
    ).trim();

  if (!walletAddress) {
    return json(res, 500, {
      success: false,
      ready: false,
      message:
        "USDTMZ_TRON_WALLET_ADDRESS não configurado."
    });
  }

  /* =====================================================
     VALIDAR ENDEREÇO TRON
     ===================================================== */

  if (
    !TronWeb.isAddress(
      walletAddress
    )
  ) {
    return json(res, 500, {
      success: false,
      ready: false,
      message:
        "Endereço da carteira TRON inválido."
    });
  }

  let walletHex;

  try {
    walletHex =
      TronWeb.address.toHex(
        walletAddress
      );
  } catch (error) {
    console.error(
      "TRON ADDRESS ERROR:",
      error
    );

    return json(res, 500, {
      success: false,
      ready: false,
      message:
        "Não foi possível converter o endereço TRON."
    });
  }

  /* =====================================================
     RESPOSTA
     ===================================================== */

  return json(res, 200, {
    success: true,
    ready: true,

    network: "TRON",
    network_name: "TRON Mainnet",

    wallet_address:
      walletAddress,

    wallet: {
      address:
        walletAddress,

      address_hex:
        walletHex
    },

    usdt: {
      network: "TRON",
      standard: "TRC20",
      contract:
        USDT_CONTRACT,
      decimals: 6
    },

    trx: {
      network: "TRON",
      native: true,
      decimals: 6
    },

    configured: true,

    updated_at:
      new Date().toISOString()
  });
}
