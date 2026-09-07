import { createHmac, timingSafeEqual } from "node:crypto";
import { TronWeb } from "tronweb";

const COOKIE_NAME = "usdtmz_admin_session";

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

  return cookie.substring(name.length + 1);
}

function verifyAdminSession(req) {
  const token = getCookie(req, COOKIE_NAME);
  const secret = process.env.ADMIN_SESSION_SECRET;

  if (!token || !secret) {
    return null;
  }

  const parts = token.split(".");

  if (parts.length !== 2) {
    return null;
  }

  const [data, signature] = parts;

  const expected = createHmac("sha256", secret)
    .update(data)
    .digest("base64url");

  if (!safeCompare(signature, expected)) {
    return null;
  }

  try {
    const payload = JSON.parse(
      Buffer.from(data, "base64url").toString("utf8")
    );

    if (!payload.exp || Date.now() > Number(payload.exp)) {
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

export default async function handler(req, res) {
  if (req.method !== "GET") {
    return json(res, 405, {
      success: false,
      message: "Método não permitido."
    });
  }

  const session = verifyAdminSession(req);

  if (!session) {
    return json(res, 401, {
      success: false,
      authenticated: false,
      message: "Sessão Admin inválida ou expirada."
    });
  }

  const walletAddress = String(
    process.env.USDTMZ_TRON_WALLET_ADDRESS || ""
  ).trim();

  if (!walletAddress) {
    return json(res, 500, {
      success: false,
      ready: false,
      message:
        "USDTMZ_TRON_WALLET_ADDRESS não configurado."
    });
  }

  try {
    if (!TronWeb.isAddress(walletAddress)) {
      return json(res, 500, {
        success: false,
        ready: false,
        message:
          "USDTMZ_TRON_WALLET_ADDRESS não é um endereço TRON válido."
      });
    }

    const walletHex = TronWeb.address.toHex(walletAddress);

    return json(res, 200, {
      success: true,
      ready: true,

      network: "TRON",
      network_name: "TRON Mainnet",

      wallet: {
        address: walletAddress,
        address_hex: walletHex,
        type: "USDTMZ_TRON_WALLET"
      },

      assets: {
        USDT: {
          standard: "TRC-20",
          contract:
            "TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t",
          decimals: 6
        },

        TRX: {
          native: true,
          decimals: 6
        }
      },

      configured: {
        wallet: true,
        network: true
      },

      updated_at: new Date().toISOString()
    });
  } catch (error) {
    console.error(
      "TRON WALLET INFO ERROR:",
      error
    );

    return json(res, 500, {
      success: false,
      ready: false,
      message:
        "Não foi possível obter as informações da carteira TRON.",
      detail:
        error?.message || "Erro desconhecido."
    });
  }
}
