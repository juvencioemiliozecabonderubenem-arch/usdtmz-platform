import { neon } from "@neondatabase/serverless";
import { createHmac, timingSafeEqual } from "node:crypto";
import { TronWeb } from "tronweb";

const COOKIE_NAME = "usdtmz_admin_session";

const USDT_CONTRACT = "TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t";
const USDT_DECIMALS = 6;

// Limite máximo de energia/gasto de TRX permitido pela operação.
// 100 TRX em sun.
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
    .find(item => item.startsWith(`${COOKIE_NAME}=`));

  if (!cookie) {
    return null;
  }

  return cookie.substring(COOKIE_NAME.length + 1);
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
  return /^[0-9a-fA-F]{64}$/.test(String(value || ""));
}

function normalizeAmount(value) {
  if (value === null || value === undefined) {
    return null;
  }

  const text = String(value).trim();

  if (!/^\d+(\.\d{1,6})?$/.test(text)) {
    return null;
  }

  const parts = text.split(".");

  const whole = parts[0];

  const decimal = (parts[1] || "")
    .padEnd(USDT_DECIMALS, "0");

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

function getErrorMessage(error) {
  if (!error) {
    return "Erro desconhecido.";
  }

  if (typeof error === "string") {
    return error;
  }

  if (error.message) {
    return error.message;
  }

  try {
    return JSON.stringify(error);
  } catch {
    return "Erro desconhecido.";
  }
}

async function restoreAuthorized(sql, withdrawalId) {
  await sql`
    UPDATE withdrawals
    SET
      status = 'AUTHORIZED',
      updated_at = NOW()
    WHERE withdrawal_id = ${String(withdrawalId)}
    AND UPPER(status) = 'PROCESSING'
    AND (tx_hash IS NULL OR tx_hash = '')
  `;
}

async function getTransactionInfo(tronWeb, txHash) {
  try {
    return await tronWeb.trx.getTransactionInfo(txHash);
  } catch {
    return null;
  }
}

async function waitForTransaction(tronWeb, txHash) {
  const maxAttempts = 6;
  const delayMs = 2000;

  for (let attempt = 0; attempt < maxAttempts; attempt++) {
    const info = await getTransactionInfo(
      tronWeb,
      txHash
    );

    if (info && info.id) {
      return info;
    }

    await new Promise(resolve =>
      setTimeout(resolve, delayMs)
    );
  }

  return null;
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

  const privateKey =
    process.env.TRON_PRIVATE_KEY;

  const configuredWallet =
    process.env.USDTMZ_TRON_WALLET_ADDRESS;

  const tronApiKey =
    process.env.TRON_PRO_API_KEY;

  /*
   * A chave privada NÃO é exigida durante o primeiro
   * teste de deploy. Assim conseguimos confirmar
   * que a função está corretamente instalada.
   */
  if (!secret || !databaseUrl || !configuredWallet) {
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

  if (!privateKey) {
    return res.status(503).json({
      success: false,
      ready: false,
      message:
        "A carteira de envio ainda não está configurada no servidor."
    });
  }

  if (!isValidPrivateKey(privateKey)) {
    return res.status(500).json({
      success: false,
      message:
        "TRON_PRIVATE_KEY inválida."
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

  const withdrawalIdText =
    String(withdrawalId).trim();

  if (!withdrawalIdText) {
    return res.status(400).json({
      success: false,
      message:
        "withdrawal_id inválido."
    });
  }

  try {
    const sql =
      neon(databaseUrl);

    /*
     * PRIMEIRA PROTEÇÃO:
     *
     * Somente um levantamento AUTHORIZED pode
     * entrar em PROCESSING.
     *
     * Isso evita dois cliques simultâneos do Admin
     * iniciarem duas operações.
     */
    const locked =
      await sql`
        UPDATE withdrawals
        SET
          status = 'PROCESSING',
          updated_at = NOW()
        WHERE withdrawal_id = ${withdrawalIdText}
        AND UPPER(status) = 'AUTHORIZED'
        AND (tx_hash IS NULL OR tx_hash = '')
        RETURNING
          id,
          withdrawal_id,
          user_id,
          amount,
          amount_requested,
          amount_to_send,
          withdrawal_fee,
          asset,
          network,
          destination_address,
          status,
          tx_hash,
          created_at,
          updated_at,
          order_id
      `;

    /*
     * Se não conseguiu fazer AUTHORIZED → PROCESSING,
     * verificamos o estado atual.
     */
    if (locked.length === 0) {
      const existing =
        await sql`
          SELECT
            withdrawal_id,
            status,
            tx_hash
          FROM withdrawals
          WHERE withdrawal_id = ${withdrawalIdText}
          LIMIT 1
        `;

      if (existing.length === 0) {
        return res.status(404).json({
          success: false,
          message:
            "Levantamento não encontrado."
        });
      }

      if (existing[0].tx_hash) {
        return res.status(409).json({
          success: false,
          message:
            "Este levantamento já possui uma transação.",
          tx_hash:
            existing[0].tx_hash,
          status:
            existing[0].status
        });
      }

      return res.status(409).json({
        success: false,
        message:
          `O levantamento não está autorizado para processamento. Estado atual: ${existing[0].status}.`
      });
    }

    const withdrawal =
      locked[0];

    /*
     * VALIDAÇÃO DO ATIVO
     */
    const asset =
      String(
        withdrawal.asset || ""
      ).trim().toUpperCase();

    if (asset !== "USDT") {
      await restoreAuthorized(
        sql,
        withdrawalIdText
      );

      return res.status(400).json({
        success: false,
        message:
          "Este processamento aceita somente USDT."
      });
    }

    /*
     * VALIDAÇÃO DA REDE
     */
    const network =
      String(
        withdrawal.network || ""
      ).trim().toUpperCase();

    const validNetwork =
      network === "TRON" ||
      network === "TRC20" ||
      network === "TRC-20";

    if (!validNetwork) {
      await restoreAuthorized(
        sql,
        withdrawalIdText
      );

      return res.status(400).json({
        success: false,
        message:
          "A rede do levantamento não é TRON TRC-20."
      });
    }

    /*
     * DESTINO
     */
    const destination =
      String(
        withdrawal.destination_address || ""
      ).trim();

    if (!destination) {
      await restoreAuthorized(
        sql,
        withdrawalIdText
      );

      return res.status(400).json({
        success: false,
        message:
          "Endereço de destino não informado."
      });
    }

    /*
     * VALIDAÇÃO REAL DO ENDEREÇO TRON
     */
    const tronWeb =
      getTronWeb(
        privateKey,
        tronApiKey
      );

    if (!tronWeb.isAddress(destination)) {
      await restoreAuthorized(
        sql,
        withdrawalIdText
      );

      return res.status(400).json({
        success: false,
        message:
          "Endereço TRON de destino inválido."
      });
    }

    /*
     * CONFIRMAÇÃO DA CARTEIRA DE ORIGEM
     */
    const senderAddress =
      tronWeb.address.fromPrivateKey(
        privateKey
      );

    if (!senderAddress) {
      await restoreAuthorized(
        sql,
        withdrawalIdText
      );

      return res.status(500).json({
        success: false,
        message:
          "Não foi possível identificar a carteira da chave privada."
      });
    }

    if (
      senderAddress !==
      configuredWallet.trim()
    ) {
      await restoreAuthorized(
        sql,
        withdrawalIdText
      );

      return res.status(500).json({
        success: false,
        message:
          "A chave privada configurada não corresponde à carteira USDTMZ."
      });
    }

    /*
     * VALOR
     *
     * Preferimos amount_to_send quando existir.
     * Caso contrário usamos amount.
     */
    const amountValue =
      withdrawal.amount_to_send ??
      withdrawal.amount ??
      withdrawal.amount_requested;

    const amount =
      normalizeAmount(
        amountValue
      );

    if (!amount) {
      await restoreAuthorized(
        sql,
        withdrawalIdText
      );

      return res.status(400).json({
        success: false,
        message:
          "Valor de USDT inválido."
      });
    }

    /*
     * NÃO PERMITIMOS ENVIAR PARA A PRÓPRIA CARTEIRA.
     */
    if (
      destination ===
      senderAddress
    ) {
      await restoreAuthorized(
        sql,
        withdrawalIdText
      );

      return res.status(400).json({
        success: false,
        message:
          "O endereço de destino não pode ser a própria carteira USDTMZ."
      });
    }

    /*
     * CONTRATO USDT TRC-20
     */
    const contract =
      await tronWeb.contract().at(
        USDT_CONTRACT
      );

    /*
     * SALDO REAL DE USDT
     */
    const usdtBalanceRaw =
      await contract
        .balanceOf(senderAddress)
        .call();

    const usdtBalance =
      BigInt(
        usdtBalanceRaw.toString()
      );

    if (
      usdtBalance <
      amount.baseUnits
    ) {
      await restoreAuthorized(
        sql,
        withdrawalIdText
      );

      return res.status(400).json({
        success: false,
        message:
          "Saldo USDT insuficiente para esta retirada."
      });
    }

    /*
     * SALDO DE TRX
     *
     * O TRX é necessário para recursos da rede.
     */
    const trxBalance =
      await tronWeb.trx.getBalance(
        senderAddress
      );

    if (
      !Number.isFinite(
        Number(trxBalance)
      )
    ) {
      await restoreAuthorized(
        sql,
        withdrawalIdText
      );

      return res.status(503).json({
        success: false,
        message:
          "Não foi possível verificar o saldo TRX."
      });
    }

    if (
      Number(trxBalance) <= 0
    ) {
      await restoreAuthorized(
        sql,
        withdrawalIdText
      );

      return res.status(400).json({
        success: false,
        message:
          "A carteira não possui TRX para pagar os recursos da rede."
      });
    }

    /*
     * VERIFICAÇÃO EXTRA ANTES DO ENVIO:
     *
     * Se o levantamento já tiver TX Hash, nunca enviamos
     * novamente.
     */
    const current =
      await sql`
        SELECT
          status,
          tx_hash
        FROM withdrawals
        WHERE withdrawal_id = ${withdrawalIdText}
        LIMIT 1
      `;

    if (
      current.length === 0
    ) {
      return res.status(404).json({
        success: false,
        message:
          "Levantamento não encontrado."
      });
    }

    if (
      current[0].tx_hash
    ) {
      return res.status(409).json({
        success: false,
        message:
          "Este levantamento já possui TX Hash. Nenhum novo envio foi realizado.",
        tx_hash:
          current[0].tx_hash
      });
    }

    /*
     * ENVIO REAL
     *
     * IMPORTANTE:
     * Neste momento a chave privada já está no servidor.
     * Ela nunca é enviada ao navegador.
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
            feeLimit:
              DEFAULT_FEE_LIMIT,
            callValue: 0,
            shouldPollResponse: false
          });
    } catch (sendError) {
      await restoreAuthorized(
        sql,
        withdrawalIdText
      );

      return res.status(502).json({
        success: false,
        message:
          "A transação não foi enviada para a rede TRON.",
        error:
          getErrorMessage(sendError)
      });
    }

    if (!txHash) {
      await restoreAuthorized(
        sql,
        withdrawalIdText
      );

      return res.status(502).json({
        success: false,
        message:
          "A rede TRON não retornou TX Hash."
      });
    }

    const txHashText =
      String(txHash);

    /*
     * GUARDA O TX HASH IMEDIATAMENTE.
     *
     * A partir daqui o levantamento não pode voltar
     * simplesmente para AUTHORIZED.
     */
    const saved =
      await sql`
        UPDATE withdrawals
        SET
          tx_hash = ${txHashText},
          status = 'PROCESSING',
          updated_at = NOW()
        WHERE withdrawal_id = ${withdrawalIdText}
        AND UPPER(status) = 'PROCESSING'
        AND (tx_hash IS NULL OR tx_hash = '')
        RETURNING
          withdrawal_id,
          status,
          tx_hash
      `;

    /*
     * Se não conseguiu guardar o TX Hash, NÃO fazemos
     * outra transferência automaticamente.
     *
     * Isso é fundamental para evitar double-send.
     */
    if (saved.length === 0) {
      return res.status(500).json({
        success: false,
        message:
          "A transação foi enviada, mas não foi possível atualizar o registro. NÃO tente processar novamente automaticamente.",
        tx_hash:
          txHashText,
        requires_reconciliation: true
      });
    }

    /*
     * Tenta localizar a informação da transação.
     *
     * Se ainda não estiver disponível, mantemos
     * PROCESSING e devolvemos o TX Hash.
     */
    const transactionInfo =
      await waitForTransaction(
        tronWeb,
        txHashText
      );

    if (!transactionInfo) {
      return res.status(202).json({
        success: true,
        status: "PROCESSING",
        message:
          "USDT enviado para a rede TRON. A confirmação ainda está pendente.",
        withdrawal_id:
          withdrawalIdText,
        tx_hash:
          txHashText,
        amount_usdt:
          amount.display,
        destination,
        requires_confirmation: true
      });
    }

    /*
     * NÃO marcamos COMPLETED aqui apenas porque existe
     * TX Hash.
     *
     * A confirmação final deve verificar:
     * - contrato USDT correto
     * - destino correto
     * - quantidade correta
     * - sucesso da execução
     * - confirmação na blockchain
     *
     * O estado continua PROCESSING até essa validação.
     */
    return res.status(200).json({
      success: true,
      status: "PROCESSING",
      message:
        "USDT enviado com sucesso para a rede TRON. TX Hash registrado. A confirmação final será feita pela verificação da blockchain.",
      withdrawal_id:
        withdrawalIdText,
      tx_hash:
        txHashText,
      amount_usdt:
        amount.display,
      destination,
      transaction_found: true
    });

  } catch (error) {
    console.error(
      "ADMIN WITHDRAWAL PROCESS ERROR:",
      error
    );

    return res.status(500).json({
      success: false,
      message:
        "Erro interno ao processar o levantamento.",
      error:
        getErrorMessage(error)
    });
  }
}
