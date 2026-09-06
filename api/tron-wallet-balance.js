import { createHmac, timingSafeEqual } from "node:crypto";
import { TronWeb } from "tronweb";

const COOKIE_NAME = "usdtmz_admin_session";

const USDT_CONTRACT =
  "TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t";

const TRON_GRID =
  "https://api.trongrid.io";

const USDT_DECIMALS = 6;


/* =========================================================
   JSON
   ========================================================= */

function json(res, status, body) {
  return res.status(status).json(body);
}


/* =========================================================
   COMPARAÇÃO SEGURA
   ========================================================= */

function safeCompare(a, b) {
  const A = Buffer.from(String(a));
  const B = Buffer.from(String(b));

  if (A.length !== B.length) {
    return false;
  }

  return timingSafeEqual(A, B);
}


/* =========================================================
   COOKIE
   ========================================================= */

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


/* =========================================================
   ADMIN SESSION
   ========================================================= */

function verifyAdminSession(req) {
  const token =
    getCookie(
      req,
      COOKIE_NAME
    );

  const secret =
    process.env.ADMIN_SESSION_SECRET;

  if (!token || !secret) {
    return null;
  }

  const parts =
    token.split(".");

  if (parts.length !== 2) {
    return null;
  }

  const [data, signature] =
    parts;

  const expected =
    createHmac(
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
    return null;
  }

  try {

    const payload =
      JSON.parse(
        Buffer
          .from(
            data,
            "base64url"
          )
          .toString("utf8")
      );

    if (
      !payload.exp ||
      Date.now() >
        Number(payload.exp)
    ) {
      return null;
    }

    if (
      payload.id !== "admin"
    ) {
      return null;
    }

    return payload;

  } catch {
    return null;
  }
}


/* =========================================================
   SUN → TRX
   ========================================================= */

function sunToTrx(value) {

  const sun =
    BigInt(
      value || 0
    );

  const whole =
    sun / 1_000_000n;

  const fraction =
    (sun % 1_000_000n)
      .toString()
      .padStart(6, "0");

  return Number(
    `${whole}.${fraction}`
  );
}


/* =========================================================
   USDT BASE UNITS → USDT
   ========================================================= */

function baseUnitsToUsdt(
  value
) {

  const units =
    BigInt(
      value || 0
    );

  const whole =
    units / 1_000_000n;

  const fraction =
    (units % 1_000_000n)
      .toString()
      .padStart(6, "0");

  return Number(
    `${whole}.${fraction}`
  );
}


/* =========================================================
   HANDLER
   ========================================================= */

export default async function handler(
  req,
  res
) {

  /* =======================================================
     MÉTODO
     ======================================================= */

  if (
    req.method !== "GET"
  ) {
    return json(
      res,
      405,
      {
        success: false,
        message:
          "Método não permitido."
      }
    );
  }


  /* =======================================================
     ADMIN
     ======================================================= */

  const session =
    verifyAdminSession(req);

  if (!session) {
    return json(
      res,
      401,
      {
        success: false,
        authenticated: false,
        message:
          "Sessão Admin inválida ou expirada."
      }
    );
  }


  /* =======================================================
     VARIÁVEIS
     ======================================================= */

  const walletAddress =
    String(
      process.env
        .USDTMZ_TRON_WALLET_ADDRESS ||
        ""
    ).trim();

  const apiKey =
    String(
      process.env.TRON_PRO_API_KEY ||
        ""
    ).trim();


  if (!walletAddress) {
    return json(
      res,
      500,
      {
        success: false,
        ready: false,
        message:
          "USDTMZ_TRON_WALLET_ADDRESS não configurado."
      }
    );
  }


  if (!apiKey) {
    return json(
      res,
      500,
      {
        success: false,
        ready: false,
        message:
          "TRON_PRO_API_KEY não configurada."
      }
    );
  }


  try {

    /* =====================================================
       VALIDAR ENDEREÇO
       ===================================================== */

    if (
      !TronWeb.isAddress(
        walletAddress
      )
    ) {
      return json(
        res,
        500,
        {
          success: false,
          ready: false,
          message:
            "O endereço USDTMZ_TRON_WALLET_ADDRESS não é válido."
        }
      );
    }


    /* =====================================================
       TRONWEB
       ===================================================== */

    const tronWeb =
      new TronWeb({
        fullHost:
          TRON_GRID,

        headers: {
          "TRON-PRO-API-KEY":
            apiKey
        }
      });


    /* =====================================================
       1. SALDO TRX
       ===================================================== */

    const trxSun =
      await tronWeb.trx.getBalance(
        walletAddress
      );

    const trxBalance =
      sunToTrx(
        trxSun
      );


    /* =====================================================
       2. CONTRATO USDT
       ===================================================== */

    const contract =
      await tronWeb.contract().at(
        USDT_CONTRACT
      );


    /* =====================================================
       3. BALANCE OF
       ===================================================== */

    const usdtRaw =
      await contract
        .balanceOf(
          walletAddress
        )
        .call();


    /*
     * Dependendo da versão do TronWeb,
     * o retorno pode ser:
     *
     * bigint
     * number
     * string
     * Uint8Array
     * objeto wrapper
     */

    let usdtBaseUnits;


    if (
      typeof usdtRaw ===
      "bigint"
    ) {

      usdtBaseUnits =
        usdtRaw;

    } else if (
      typeof usdtRaw ===
      "number"
    ) {

      usdtBaseUnits =
        BigInt(
          Math.trunc(
            usdtRaw
          )
        );

    } else if (
      typeof usdtRaw ===
      "string"
    ) {

      /*
       * Normalmente o TronWeb
       * devolve o valor decimal.
       */
      usdtBaseUnits =
        BigInt(
          usdtRaw
        );

    } else if (
      usdtRaw &&
      typeof usdtRaw ===
      "object" &&
      "toString" in usdtRaw
    ) {

      usdtBaseUnits =
        BigInt(
          usdtRaw.toString()
        );

    } else {

      throw new Error(
        "O contrato USDT retornou um formato de saldo não reconhecido."
      );
    }


    /* =====================================================
       4. SALDO USDT
       ===================================================== */

    const usdtBalance =
      baseUnitsToUsdt(
        usdtBaseUnits
      );


    /* =====================================================
       RESULTADO
       ===================================================== */

    return json(
      res,
      200,
      {
        success: true,

        ready: true,

        network:
          "TRON",

        asset:
          "USDT",

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
            String(trxSun)
        },

        updated_at:
          new Date().toISOString()
      }
    );


  } catch (error) {

    console.error(
      "TRON WALLET BALANCE ERROR:",
      error
    );

    return json(
      res,
      502,
      {
        success: false,

        ready: false,

        message:
          "Erro ao consultar saldo da carteira TRON.",

        detail:
          error?.message ||
          "Erro desconhecido."
      }
    );
  }
}
