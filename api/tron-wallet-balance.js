import { neon } from "@neondatabase/serverless";
import { createHmac, timingSafeEqual } from "node:crypto";
import { TronWeb } from "tronweb";

const COOKIE_NAME = "usdtmz_admin_session";

const USDT_CONTRACT =
  "TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t";

const USDT_DECIMALS = 6;

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
    .find((item) =>
      item.startsWith(`${name}=`)
    );

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

function getDatabaseUrl() {
  return (
    process.env.URL_DO_BANCO_DE_DADOS ||
    process.env.POSTGRES_URL ||
    process.env.DATABASE_URL ||
    process.env.POSTGRES_URL_NON_POOLING ||
    process.env.DATABASE_URL_UNPOOLED
  );
}

function getTronWeb() {
  const apiKey =
    process.env.TRON_PRO_API_KEY;

  const options = {
    fullHost: "https://api.trongrid.io"
  };

  if (apiKey) {
    options.headers = {
      "TRON-PRO-API-KEY": apiKey
    };
  }

  return new TronWeb(options);
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

  const walletAddress =
    String(
      process.env.USDTMZ_TRON_WALLET_ADDRESS || ""
    ).trim();

  if (!walletAddress) {
    return json(res, 500, {
      success: false,
      ready: false,
      message:
        "USDTMZ_TRON_WALLET_ADDRESS não está configurado."
    });
  }

  try {
    const tronWeb = getTronWeb();

    if (!tronWeb.isAddress(walletAddress)) {
      return json(res, 500, {
        success: false,
        ready: false,
        message:
          "O endereço da carteira USDTMZ não é um endereço TRON válido."
      });
    }

    /*
     * =====================================================
     * SALDO TRX
     * =====================================================
     */

    const trxBalanceSun =
      await tronWeb.trx.getBalance(
        walletAddress
      );

    const trxBalance =
      Number(trxBalanceSun) / 1_000_000;

    /*
     * =====================================================
     * SALDO USDT TRC-20
     * =====================================================
     */

    const contract =
      await tronWeb.contract().at(
        USDT_CONTRACT
      );

    const usdtBalanceRaw =
      await contract
        .balanceOf(walletAddress)
        .call();

    const usdtBaseUnits =
      BigInt(
        usdtBalanceRaw.toString()
      );

    const usdtBalance =
      Number(usdtBaseUnits) /
      10 ** USDT_DECIMALS;

    /*
     * =====================================================
     * RETORNO
     * =====================================================
     */

    return json(res, 200, {
      success: true,
      network: "TRON",
      asset: "USDT",
      wallet_address: walletAddress,

      usdt: {
        balance: usdtBalance,
        base_units: usdtBaseUnits.toString(),
        decimals: USDT_DECIMALS,
        contract: USDT_CONTRACT
      },

      trx: {
        balance: trxBalance,
        sun: String(trxBalanceSun)
      },

      updated_at: new Date().toISOString()
    });
  } catch (error) {
    console.error(
      "TRON WALLET BALANCE ERROR:",
      error
    );

    return json(res, 502, {
      success: false,
      message:
        "Erro ao consultar saldo da carteira TRON.",
      error:
        error?.message ||
        "Erro desconhecido."
    });
  }
}
