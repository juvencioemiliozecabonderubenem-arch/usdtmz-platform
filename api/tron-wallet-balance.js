import { createHmac, timingSafeEqual } from "node:crypto";
import { TronWeb } from "tronweb";

const COOKIE_NAME = "usdtmz_admin_session";

const TRON_GRID = "https://api.trongrid.io";

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

async function tronRequest(path, body, apiKey) {
  const response = await fetch(`${TRON_GRID}${path}`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Accept: "application/json",
      "TRON-PRO-API-KEY": apiKey
    },
    body: JSON.stringify(body)
  });

  const text = await response.text();

  let data = {};

  try {
    data = text ? JSON.parse(text) : {};
  } catch {
    data = {
      message: text
    };
  }

  if (!response.ok) {
    const message =
      data?.Error ||
      data?.error ||
      data?.message ||
      text ||
      "Resposta inválida da TRON.";

    throw new Error(
      `TRON API HTTP ${response.status}: ${message}`
    );
  }

  if (data?.success === false) {
    throw new Error(
      data?.Error ||
      data?.error ||
      data?.message ||
      "TRON API recusou a consulta."
    );
  }

  if (
    data?.result &&
    data.result.result === false
  ) {
    throw new Error(
      data.result.message ||
      "A TRON recusou a consulta."
    );
  }

  return data;
}

function sunToTrx(value) {
  const sun = BigInt(value || 0);

  const whole = sun / 1_000_000n;

  const fraction = (sun % 1_000_000n)
    .toString()
    .padStart(6, "0");

  return Number(`${whole}.${fraction}`);
}

function baseUnitsToUsdt(value) {
  const units = BigInt(value || 0);

  const whole = units / 1_000_000n;

  const fraction = (units % 1_000_000n)
    .toString()
    .padStart(6, "0");

  return Number(`${whole}.${fraction}`);
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

  const apiKey = String(
    process.env.TRON_PRO_API_KEY || ""
  ).trim();

  if (!walletAddress) {
    return json(res, 500, {
      success: false,
      ready: false,
      message:
        "USDTMZ_TRON_WALLET_ADDRESS não configurado."
    });
  }

  if (!apiKey) {
    return json(res, 500, {
      success: false,
      ready: false,
      message:
        "TRON_PRO_API_KEY não configurada."
    });
  }

  try {
    if (!TronWeb.isAddress(walletAddress)) {
      return json(res, 500, {
        success: false,
        ready: false,
        message:
          "O endereço USDTMZ_TRON_WALLET_ADDRESS não é válido."
      });
    }

    const walletHex =
      TronWeb.address.toHex(walletAddress);

    const contractHex =
      TronWeb.address.toHex(USDT_CONTRACT);

    if (!/^41[0-9a-fA-F]{40}$/.test(walletHex)) {
      throw new Error(
        "Endereço da carteira TRON convertido para HEX inválido."
      );
    }

    if (!/^41[0-9a-fA-F]{40}$/.test(contractHex)) {
      throw new Error(
        "Endereço do contrato USDT convertido para HEX inválido."
      );
    }

    /*
     * =====================================================
     * SALDO TRX
     * =====================================================
     */

    const account = await tronRequest(
      "/wallet/getaccount",
      {
        address: walletHex,
        visible: false
      },
      apiKey
    );

    const trxSun = BigInt(
      account?.balance || 0
    );

    const trxBalance = sunToTrx(trxSun);

    /*
     * =====================================================
     * SALDO USDT
     * =====================================================
     */

    const ownerParameter = walletHex
      .slice(2)
      .padStart(64, "0");

    if (
      !/^[0-9a-fA-F]{64}$/.test(
        ownerParameter
      )
    ) {
      throw new Error(
        "Parâmetro owner_address inválido para balanceOf."
      );
    }

    const constantResult = await tronRequest(
      "/wallet/triggerconstantcontract",
      {
        owner_address: walletHex,
        contract_address: contractHex,
        function_selector: "balanceOf(address)",
        parameter: ownerParameter,
        visible: false
      },
      apiKey
    );

    const rawBalance =
      constantResult?.constant_result?.[0];

    if (
      typeof rawBalance !== "string" ||
      !/^[0-9a-fA-F]+$/.test(rawBalance)
    ) {
      throw new Error(
        "TRON não retornou um saldo USDT válido."
      );
    }

    const usdtBaseUnits = BigInt(
      `0x${rawBalance}`
    );

    const usdtBalance =
      baseUnitsToUsdt(usdtBaseUnits);

    /*
     * =====================================================
     * RESPOSTA
     * =====================================================
     *
     * Mantemos o formato antigo:
     *
     * usdt.balance
     * trx.balance
     *
     * e acrescentamos:
     *
     * balances.USDT
     * balances.TRX
     *
     * para o Admin.
     */

    return json(res, 200, {
      success: true,
      ready: true,

      network: "TRON",
      asset: "USDT",

      wallet_address: walletAddress,

      balances: {
        USDT: usdtBalance,
        TRX: trxBalance
      },

      usdt: {
        balance: usdtBalance,
        base_units: usdtBaseUnits.toString(),
        decimals: USDT_DECIMALS,
        contract: USDT_CONTRACT
      },

      trx: {
        balance: trxBalance,
        sun: trxSun.toString()
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
      ready: false,
      message:
        "Erro ao consultar saldo da carteira TRON.",
      detail:
        error?.message ||
        "Erro desconhecido."
    });
  }
}
