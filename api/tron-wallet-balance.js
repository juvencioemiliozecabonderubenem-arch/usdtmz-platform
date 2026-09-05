import { createHmac, timingSafeEqual } from "node:crypto";

const COOKIE_NAME = "usdtmz_admin_session";

const USDT_CONTRACT =
  "TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t";

function safeCompare(a, b) {
  const A = Buffer.from(String(a));
  const B = Buffer.from(String(b));

  if (A.length !== B.length) {
    return false;
  }

  return timingSafeEqual(A, B);
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

  const expectedSignature = createHmac("sha256", secret)
    .update(data)
    .digest("base64url");

  if (!safeCompare(signature, expectedSignature)) {
    return null;
  }

  try {
    const payload = JSON.parse(
      Buffer.from(data, "base64url").toString("utf8")
    );

    if (!payload.exp || Date.now() > payload.exp) {
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

function getSessionToken(req) {
  const cookies = req.headers.cookie || "";

  const cookie = cookies
    .split(";")
    .map(item => item.trim())
    .find(
      item => item.startsWith(`${COOKIE_NAME}=`)
    );

  if (!cookie) {
    return null;
  }

  return cookie.substring(
    COOKIE_NAME.length + 1
  );
}

export default async function handler(req, res) {
  if (req.method !== "GET") {
    return res.status(405).json({
      success: false,
      message: "Método não permitido."
    });
  }

  const secret = process.env.ADMIN_SESSION_SECRET;

  const walletAddress =
    process.env.USDTMZ_TRON_WALLET_ADDRESS;

  const tronApiKey =
    process.env.TRON_PRO_API_KEY;

  if (!secret || !walletAddress) {
    return res.status(500).json({
      success: false,
      message: "Carteira TRON não configurada."
    });
  }

  const token = getSessionToken(req);

  const session = verifySession(
    token,
    secret
  );

  if (!session) {
    return res.status(401).json({
      success: false,
      authenticated: false,
      message: "Sessão inválida ou expirada."
    });
  }

  try {
    const headers = {
      Accept: "application/json"
    };

    if (tronApiKey) {
      headers["TRON-PRO-API-KEY"] = tronApiKey;
    }

    const accountResponse = await fetch(
      `https://api.trongrid.io/v1/accounts/${walletAddress}`,
      {
        method: "GET",
        headers
      }
    );

    if (!accountResponse.ok) {
      throw new Error(
        `Erro TronGrid account: ${accountResponse.status}`
      );
    }

    const accountData =
      await accountResponse.json();

    const account = accountData.data?.[0] || {};

    const trxSun = Number(account.balance || 0);

    const trxBalance =
      trxSun / 1_000_000;

    const trc20Response = await fetch(
      `https://api.trongrid.io/v1/accounts/${walletAddress}/transactions/trc20?contract_address=${USDT_CONTRACT}&only_confirmed=true&limit=200`,
      {
        method: "GET",
        headers
      }
    );

    if (!trc20Response.ok) {
      throw new Error(
        `Erro TronGrid TRC20: ${trc20Response.status}`
      );
    }

    const trc20Data =
      await trc20Response.json();

    let usdtBalance = 0;

    const tokens = trc20Data.data || [];

    for (const token of tokens) {
      if (
        token.token_info?.address === USDT_CONTRACT
      ) {
        const decimals =
          Number(token.token_info?.decimals ?? 6);

        const value =
          Number(token.value || 0);

        if (token.to === walletAddress) {
          usdtBalance +=
            value / Math.pow(10, decimals);
        }

        if (token.from === walletAddress) {
          usdtBalance -=
            value / Math.pow(10, decimals);
        }
      }
    }

    if (usdtBalance < 0) {
      usdtBalance = 0;
    }

    return res.status(200).json({
      success: true,
      network: "TRON",
      standard: "TRC-20",
      wallet_address: walletAddress,
      balances: {
        TRX: Number(trxBalance.toFixed(6)),
        USDT: Number(usdtBalance.toFixed(6))
      }
    });

  } catch (error) {
    console.error(
      "Erro ao consultar saldo TRON:",
      error
    );

    return res.status(500).json({
      success: false,
      message: "Erro ao consultar saldo da carteira TRON."
    });
  }
}
