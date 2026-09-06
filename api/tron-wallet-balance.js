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


/* =========================================================
   TRON GRID
   ========================================================= */

async function tronRequest(path, body, apiKey) {
  const headers = {
    "Content-Type": "application/json",
    Accept: "application/json"
  };

  /*
   * Mantém a API KEY que já está configurada
   * no Vercel.
   */
  if (apiKey) {
    headers["TRON-PRO-API-KEY"] = apiKey;
  }

  const response = await fetch(
    `${TRON_GRID}${path}`,
    {
      method: "POST",
      headers,
      body: JSON.stringify(body)
    }
  );

  const text = await response.text();

  let data = {};

  try {
    data = text
      ? JSON.parse(text)
      : {};
  } catch {
    data = {
      message: text
    };
  }

  if (!response.ok) {
    const apiMessage =
      data?.Error ||
      data?.error ||
      data?.message ||
      text ||
      "Resposta inválida da TRON.";

    throw new Error(
      `TRON API HTTP ${response.status}: ${apiMessage}`
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

  return data;
}


/* =========================================================
   CONVERTER SUN → TRX
   ========================================================= */

function sunToTrx(value) {
  const sun = BigInt(value || 0);

  const whole = sun / 1_000_000n;
  const fraction =
    (sun % 1_000_000n)
      .toString()
      .padStart(6, "0");

  return Number(
    `${whole}.${fraction}`
  );
}


/* =========================================================
   CONVERTER HEX → USDT
   ========================================================= */

function hexToUsdt(hex) {
  const value = BigInt(
    `0x${hex}`
  );

  const whole =
    value / 1_000_000n;

  const fraction =
    (value % 1_000_000n)
      .toString()
      .padStart(6, "0");

  return Number(
    `${whole}.${fraction}`
  );
}


/* =========================================================
   HANDLER
   ========================================================= */

export default async function handler(req, res) {

  if (req.method !== "GET") {
    return json(res, 405, {
      success: false,
      message: "Método não permitido."
    });
  }


  /* =======================================================
     ADMIN SESSION
     ======================================================= */

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


  /* =======================================================
     CONFIGURAÇÃO
     ======================================================= */

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

    /* =====================================================
       VALIDAR CARTEIRA
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
          "O endereço USDTMZ_TRON_WALLET_ADDRESS não é válido."
      });
    }


    /* =====================================================
       ENDEREÇOS HEX
       ===================================================== */

    const walletHex =
      TronWeb.address.toHex(
        walletAddress
      );

    const contractHex =
      TronWeb.address.toHex(
        USDT_CONTRACT
      );


    /* =====================================================
       1. SALDO TRX
       ===================================================== */

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
        account?.balance || 0
      );

    const trxBalance =
      sunToTrx(trxSun);


    /* =====================================================
       2. SALDO USDT TRC-20
       ===================================================== */

    /*
     * ABI:
     *
     * balanceOf(address)
     *
     * selector:
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
            contractHex,

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
        "TRON não retornou um saldo USDT válido."
      );
    }


    const usdtBaseUnits =
      BigInt(
        `0x${rawBalance}`
      );


    const usdtBalance =
      hexToUsdt(
        rawBalance
      );


    /* =====================================================
       RESULTADO
       ===================================================== */

    return json(res, 200, {

      success: true,

      ready: true,

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
     * Nunca devolvemos a API key.
     */

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
