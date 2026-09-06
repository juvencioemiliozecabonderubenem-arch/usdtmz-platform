import { neon } from "@neondatabase/serverless";
import { createHmac, timingSafeEqual } from "node:crypto";
import { TronWeb } from "tronweb";

const COOKIE_NAME = "usdtmz_admin_session";

const USDT_CONTRACT =
  "TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t";

const USDT_DECIMALS = 6;
const DEFAULT_FEE_LIMIT = 100_000_000;

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

function getDatabaseUrl() {
  return (
    process.env.URL_DO_BANCO_DE_DADOS ||
    process.env.POSTGRES_URL ||
    process.env.DATABASE_URL ||
    process.env.POSTGRES_URL_NON_POOLING ||
    process.env.DATABASE_URL_UNPOOLED
  );
}

function isValidPrivateKey(value) {
  return /^[0-9a-fA-F]{64}$/.test(
    String(value || "")
  );
}

function normalizeAmount(value) {
  if (
    value === null ||
    value === undefined
  ) {
    return null;
  }

  const text = String(value).trim();

  if (!/^\d+(\.\d{1,6})?$/.test(text)) {
    return null;
  }

  const [whole, decimalPart = ""] =
    text.split(".");

  const decimal = decimalPart.padEnd(
    USDT_DECIMALS,
    "0"
  );

  const baseUnits =
    BigInt(whole) * 1_000_000n +
    BigInt(decimal);

  if (baseUnits <= 0n) {
    return null;
  }

  return {
    text,
    baseUnits,
    display: (
      Number(baseUnits) / 1_000_000
    ).toFixed(6)
  };
}

function getTronWeb(privateKey, apiKey) {
  const options = {
    fullHost: "https://api.trongrid.io",
    privateKey
  };

  if (apiKey) {
    options.headers = {
      "TRON-PRO-API-KEY": apiKey
    };
  }

  return new TronWeb(options);
}

function toBigInt(value) {
  if (typeof value === "bigint") {
    return value;
  }

  if (
    value &&
    typeof value.toString === "function"
  ) {
    return BigInt(value.toString());
  }

  return BigInt(String(value));
}

function restoreAuthorized(sql, withdrawalId) {
  return sql`
    UPDATE withdrawals
    SET
      status = 'AUTHORIZED',
      updated_at = NOW()
    WHERE withdrawal_id = ${String(withdrawalId)}
    AND UPPER(status) = 'PROCESSING'
    AND (
      tx_hash IS NULL
      OR tx_hash = ''
    )
  `;
}

export default async function handler(req, res) {
  if (req.method !== "POST") {
    return res.status(405).json({
      success: false,
      message: "Método não permitido."
    });
  }

  const secret =
    process.env.ADMIN_SESSION_SECRET;

  const databaseUrl =
    getDatabaseUrl();

  if (!secret || !databaseUrl) {
    return res.status(500).json({
      success: false,
      message:
        "Configuração do servidor incompleta."
    });
  }

  const token =
    getSessionToken(req);

  const session =
    verifySession(
      token,
      secret
    );

  if (!session) {
    return res.status(401).json({
      success: false,
      authenticated: false,
      message:
        "Sessão inválida ou expirada."
    });
  }

  const body = req.body || {};

  const withdrawalId =
    body.withdrawal_id;

  if (!withdrawalId) {
    return res.status(400).json({
      success: false,
      message:
        "withdrawal_id é obrigatório."
    });
  }

  /*
   * A chave privada NÃO fica no código.
   * Ela só será configurada no Vercel
   * quando a etapa de envio real for
   * liberada.
   */
  const privateKey =
    process.env.TRON_PRIVATE_KEY;

  const configuredWallet =
    process.env.USDTMZ_TRON_WALLET_ADDRESS;

  const tronApiKey =
    process.env.TRON_PRO_API_KEY;

  /*
   * Nesta primeira fase, não permitimos
   * envio real se a carteira privada
   * ainda não estiver configurada.
   */
  if (
    !privateKey ||
    !configuredWallet
  ) {
    return res.status(503).json({
      success: false,
      message:
        "Envio TRON ainda não está ativado."
    });
  }

  if (!isValidPrivateKey(privateKey)) {
    return res.status(500).json({
      success: false,
      message:
        "Configuração TRON inválida."
    });
  }

  try {
    const sql =
      neon(databaseUrl);

    /*
     * Primeiro buscamos a retirada.
     * Não movimentamos dinheiro ainda.
     */
    const rows =
      await sql`
        SELECT
          id,
          withdrawal_id,
          user_id,
          amount,
          asset,
          network,
          destination_address,
          status,
          tx_hash,
          created_at,
          updated_at,
          order_id
        FROM withdrawals
        WHERE withdrawal_id = ${String(
          withdrawalId
        )}
        LIMIT 1
      `;

    if (rows.length === 0) {
      return res.status(404).json({
        success: false,
        message:
          "Levantamento não encontrado."
      });
    }

    const withdrawal =
      rows[0];

    /*
     * Nunca enviamos novamente algo
     * que já tenha TX Hash.
     */
    if (
      withdrawal.tx_hash &&
      String(withdrawal.tx_hash).trim()
    ) {
      return res.status(409).json({
        success: false,
        message:
          "Este levantamento já possui uma transação.",
        tx_hash:
          withdrawal.tx_hash
      });
    }

    if (
      String(withdrawal.status || "")
        .toUpperCase() !== "AUTHORIZED"
    ) {
      return res.status(409).json({
        success: false,
        message:
          `O levantamento precisa estar AUTHORIZED. Estado atual: ${withdrawal.status}.`
      });
    }

    const asset =
      String(
        withdrawal.asset || ""
      ).toUpperCase();

    if (asset !== "USDT") {
      return res.status(400).json({
        success: false,
        message:
          "O levantamento não é de USDT."
      });
    }

    const network =
      String(
        withdrawal.network || ""
      ).toUpperCase();

    if (
      network !== "TRON" &&
      network !== "TRC-20"
    ) {
      return res.status(400).json({
        success: false,
        message:
          "A rede precisa ser TRON/TRC-20."
      });
    }

    const destination =
      String(
        withdrawal.destination_address ||
        ""
      ).trim();

    if (!destination) {
      return res.status(400).json({
        success: false,
        message:
          "Endereço TRON de destino não informado."
      });
    }

    if (
      !TronWeb.isAddress(destination)
    ) {
      return res.status(400).json({
        success: false,
        message:
          "Endereço TRON de destino inválido."
      });
    }

    const amount =
      normalizeAmount(
        withdrawal.amount
      );

    if (!amount) {
      return res.status(400).json({
        success: false,
        message:
          "Quantidade de USDT inválida."
      });
    }

    /*
     * A partir daqui usamos a carteira
     * somente no servidor.
     */
    const tronWeb =
      getTronWeb(
        privateKey,
        tronApiKey
      );

    const senderAddress =
      tronWeb.address.fromPrivateKey(
        privateKey
      );

    if (!senderAddress) {
      return res.status(500).json({
        success: false,
        message:
          "Não foi possível identificar a carteira TRON."
      });
    }

    if (
      senderAddress !==
      configuredWallet
    ) {
      return res.status(500).json({
        success: false,
        message:
          "A chave TRON configurada não corresponde à carteira USDTMZ."
      });
    }

    /*
     * Consulta o contrato oficial USDT
     * diretamente para obter o saldo.
     */
    const contract =
      await tronWeb
        .contract()
        .at(USDT_CONTRACT);

    const rawBalance =
      await contract
        .balanceOf(senderAddress)
        .call();

    const usdtBalance =
      toBigInt(rawBalance);

    if (
      usdtBalance <
      amount.baseUnits
    ) {
      return res.status(409).json({
        success: false,
        message:
          "Saldo USDT insuficiente.",
        available_usdt:
          (
            Number(usdtBalance) /
            1_000_000
          ).toFixed(6),
        requested_usdt:
          amount.display
      });
    }

    /*
     * Consulta o saldo TRX.
     */
    const trxBalance =
      await tronWeb.trx.getBalance(
        senderAddress
      );

    const feeLimit =
      Number(
        process.env.TRON_FEE_LIMIT ||
        DEFAULT_FEE_LIMIT
      );

    if (
      !Number.isSafeInteger(
        feeLimit
      ) ||
      feeLimit <= 0
    ) {
      return res.status(500).json({
        success: false,
        message:
          "TRON_FEE_LIMIT inválido."
      });
    }

    /*
     * Não enviamos se a carteira
     * não tiver TRX disponível.
     *
     * O limite é uma proteção mínima.
     */
    if (
      typeof trxBalance !== "number" &&
      typeof trxBalance !== "bigint"
    ) {
      return res.status(500).json({
        success: false,
        message:
          "Não foi possível verificar o saldo TRX."
      });
    }

    /*
     * BLOQUEIO ATÔMICO
     *
     * Somente uma requisição pode
     * mudar AUTHORIZED -> PROCESSING.
     */
    const locked =
      await sql`
        UPDATE withdrawals
        SET
          status = 'PROCESSING',
          updated_at = NOW()
        WHERE withdrawal_id = ${String(
          withdrawalId
        )}
        AND UPPER(status) = 'AUTHORIZED'
        AND (
          tx_hash IS NULL
          OR tx_hash = ''
        )
        RETURNING
          id,
          withdrawal_id,
          user_id,
          amount,
          asset,
          network,
          destination_address,
          status,
          tx_hash,
          created_at,
          updated_at,
          order_id
      `;

    if (locked.length === 0) {
      return res.status(409).json({
        success: false,
        message:
          "Esta retirada já está sendo processada ou foi alterada."
      });
    }

    /*
     * IMPORTANTE:
     * A transação real só acontece
     * depois do bloqueio.
     */
    let txHash;

    try {
      txHash =
        await contract
          .transfer(
            destination,
            amount.baseUnits.toString()
          )
          .send({
            feeLimit,
            callValue: 0,
            shouldPollResponse: false
          });
    } catch (sendError) {
      console.error(
        "Erro no envio TRON:",
        sendError
      );

      await restoreAuthorized(
        sql,
        withdrawalId
      );

      return res.status(502).json({
        success: false,
        message:
          "A rede TRON não confirmou o envio da transação."
      });
    }

    if (
      !txHash ||
      typeof txHash !== "string"
    ) {
      await restoreAuthorized(
        sql,
        withdrawalId
      );

      return res.status(502).json({
        success: false,
        message:
          "A rede TRON não devolveu um TX Hash válido."
      });
    }

    /*
     * Guardamos o TX Hash imediatamente.
     *
     * NÃO fazemos outro envio caso esta
     * atualização falhe.
     */
    const updated =
      await sql`
        UPDATE withdrawals
        SET
          tx_hash = ${txHash},
          status = 'PROCESSING',
          updated_at = NOW()
        WHERE withdrawal_id = ${String(
          withdrawalId
        )}
        AND UPPER(status) = 'PROCESSING'
        AND (
          tx_hash IS NULL
          OR tx_hash = ''
        )
        RETURNING
          id,
          withdrawal_id,
          user_id,
          amount,
          asset,
          network,
          destination_address,
          status,
          tx_hash,
          created_at,
          updated_at,
          order_id
      `;

    if (updated.length === 0) {
      console.error(
        "ATENÇÃO: TX enviada mas não registrada:",
        txHash
      );

      return res.status(500).json({
        success: false,
        message:
          "A transação foi enviada, mas não foi possível registrar o TX Hash. NÃO tente enviar novamente.",
        tx_hash: txHash
      });
    }

    return res.status(200).json({
      success: true,
      message:
        "USDT enviado para a rede TRON. Aguardando confirmação.",
      tx_hash: txHash,
      network: "TRON",
      asset: "USDT",
      amount_usdt:
        amount.display,
      destination,
      withdrawal:
        updated[0]
    });

  } catch (error) {
    console.error(
      "Erro no admin-send-usdt:",
      error
    );

    return res.status(500).json({
      success: false,
      message:
        "Erro interno ao processar o envio de USDT."
    });
  }
}
