import { createHmac, timingSafeEqual } from "node:crypto";
import { TronWeb } from "tronweb";

const COOKIE_NAME = "usdtmz_admin_session";

const USDT_CONTRACT =
  "TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t";

const TRON_GRID =
  "https://api.trongrid.io";

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

async function tronRequest(path, body, apiKey) {
  const response = await fetch(
    `${TRON_GRID}${path}`,
    {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Accept: "application/json",
        "TRON-PRO-API-KEY": apiKey
      },
      body: JSON.stringify(body)
    }
  );

  const text = await response.text();

  let data;

  try {
    data = text ? JSON.parse(text) : {};
  } catch {
    data = {
      message: text
    };
  }

  if (!response.ok) {
    throw new Error(
      `TRON API HTTP ${response.status}: ${
        data?.message ||
        data?.error ||
        text ||
        "Resposta inválida."
      }`
    );
  }

  if (
    data?.success === false
  ) {
    throw new Error(
      data?.message ||
      "TRON API recusou a consulta."
    );
  }

  return data;
}

export default async function handler(req, res) {
  if (req.method !== "GET") {
    return json(res, 405, {
      success: false,
      message: "Método não permitido."
    });
  }

  const session =
    verifyAdminSession(req);

  if (!session) {
    return json(res, 401, {
      success: false,
      authenticated: false,
      message:
        "Sessão Admin inválida ou expirada."
    });
  }

  const walletAddress =
    String(
      process.env.USDTMZ_TRON_WALLET_ADDRESS ||
      ""
    ).trim();

  const apiKey =
    String(
      process.env.TRON_PRO_API_KEY ||
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

  if (!apiKey) {
    return json(res, 500, {
      success: false,
      ready: false,
      message:
        "TRON_PRO_API_KEY não configurada."
    });
  }

  try {
    /*
     * Verifica se o endereço é TRON válido.
     */
    if (
      !TronWeb.isAddress(
        walletAddress
      )
    ) {
      return json(res, 500, {
        success: false,
        ready: false,
        message:
          "O endereço USDTMZ_TRON_WALLET_ADDRESS não é válido."
      });
    }

    /*
     * Converte o endereço Base58 para hexadecimal
     * no formato usado pelo TRON API.
     */
    const walletHex =
      TronWeb.address
        .toHex(walletAddress);

    /*
     * =====================================================
     * 1. SALDO TRX
     * =====================================================
     */

    const account =
      await tronRequest(
        "/wallet/getaccount",
        {
          address:
            walletAddress,
          visible: true
        },
        apiKey
      );

    const trxSun =
      BigInt(
        account?.balance ||
        0
      );

    const trxBalance =
      Number(trxSun) /
      1_000_000;

    /*
     * =====================================================
     * 2. SALDO USDT TRC-20
     * =====================================================
     *
     * balanceOf(address)
     *
     * function selector:
     * 70a08231
     */

    const ownerHex =
      walletHex
        .replace(/^41/, "")
        .padStart(64, "0");

    const constantResult =
      await tronRequest(
        "/wallet/triggerconstantcontract",
        {
          owner_address:
            walletHex,

          contract_address:
            TronWeb.address.toHex(
              USDT_CONTRACT
            ),

          function_selector:
            "balanceOf(address)",

          parameter:
            ownerHex,

          visible: true
        },
        apiKey
      );

    const rawBalance =
      constantResult
        ?.constant_result?.[0];

    if (
      !rawBalance ||
      !/^[0-9a-fA-F]+$/.test(
        rawBalance
      )
    ) {
      throw new Error(
        "TRON não retornou o saldo USDT."
      );
    }

    const usdtBaseUnits =
      BigInt(
        `0x${rawBalance}`
      );

    const usdtBalance =
      Number(
        usdtBaseUnits
      ) /
      10 ** USDT_DECIMALS;

    /*
     * =====================================================
     * RESULTADO
     * =====================================================
     */

    return json(res, 200, {
      success: true,

      network: "TRON",

      asset: "USDT",

      wallet_address:
        walletAddress,

      usdt: {
        balance:
          usdtBalance,

        base_units:
          usdtBaseUnits.toString(),

        decimals:
          USDT_DECIMALS,

        contract:
          USDT_CONTRACT
      },

      trx: {
        balance:
          trxBalance,

        sun:
          trxSun.toString()
      },

      updated_at:
        new Date().toISOString()
    });

  } catch (error) {
    console.error(
      "TRON WALLET BALANCE ERROR:",
      error
    );

    /*
     * Retornamos o erro real para o Admin,
     * sem revelar nenhuma chave ou segredo.
     */
    return json(res, 502, {
      success: false,
      message:
        "Erro ao consultar saldo da carteira TRON.",
      detail:
        error?.message ||
        "Erro desconhecido."
    });
  }
}
