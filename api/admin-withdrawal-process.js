import { neon } from "@neondatabase/serverless";
import { createHmac, timingSafeEqual } from "node:crypto";
import { TronWeb } from "tronweb";

const COOKIE_NAME = "usdtmz_admin_session";

const USDT_CONTRACT =
  "TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t";

const USDT_DECIMALS = 6;

// 100 TRX em sun.
const DEFAULT_FEE_LIMIT = 100_000_000;

const TRON_API_BASE =
  "https://api.trongrid.io";

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

function getSessionToken(req) {
  const cookies = req.headers.cookie || "";

  const cookie = cookies
    .split(";")
    .map((item) => item.trim())
    .find((item) =>
      item.startsWith(`${COOKIE_NAME}=`)
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

function getTronWeb(
  privateKey,
  apiKey
) {
  const options = {
    fullHost: TRON_API_BASE,
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

/*
 * =========================================================
 * LEITURA DIRETA DO SALDO USDT TRC-20
 * =========================================================
 *
 * Esta função NÃO usa:
 *
 * tronWeb.contract().at(...).balanceOf(...).call()
 *
 * porque essa chamada estava causando:
 *
 * owner_address isn't set
 *
 * Em vez disso, usamos diretamente:
 *
 * /wallet/triggerconstantcontract
 *
 * informando explicitamente:
 *
 * owner_address
 * contract_address
 * function_selector
 * parameter
 *
 * balanceOf(address)
 */

async function getUsdtBalanceBaseUnits(
  ownerAddress,
  tronApiKey
) {
  if (!ownerAddress) {
    throw new Error(
      "Endereço da carteira USDTMZ não informado."
    );
  }

  if (!tronApiKey) {
    throw new Error(
      "TRON_PRO_API_KEY não configurada."
    );
  }

  const tronWeb =
    new TronWeb({
      fullHost: TRON_API_BASE
    });

  if (
    !tronWeb.isAddress(
      ownerAddress
    )
  ) {
    throw new Error(
      "Endereço da carteira USDTMZ inválido."
    );
  }

  /*
   * Endereço TRON em hexadecimal:
   *
   * 41 + 20 bytes
   *
   * Para ABI precisamos somente dos
   * 20 bytes sem o prefixo 41.
   */
  const ownerHex =
    tronWeb.address
      .toHex(ownerAddress)
      .replace(/^41/, "");

  /*
   * ABI:
   *
   * balanceOf(address)
   *
   * O endereço precisa ocupar 32 bytes,
   * portanto adicionamos zeros à esquerda.
   */
  const parameter =
    ownerHex.padStart(64, "0");

  const response =
    await fetch(
      `${TRON_API_BASE}/wallet/triggerconstantcontract`,
      {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "TRON-PRO-API-KEY":
            tronApiKey
        },
        body: JSON.stringify({
          owner_address:
            ownerAddress,
          contract_address:
            USDT_CONTRACT,
          function_selector:
            "balanceOf(address)",
          parameter,
          call_value: 0,
          visible: true
        })
      }
    );

  const responseText =
    await response.text();

  if (!response.ok) {
    throw new Error(
      `TRON API HTTP ${response.status}: ${responseText}`
    );
  }

  let data;

  try {
    data =
      JSON.parse(
        responseText
      );
  } catch {
    throw new Error(
      "A resposta da TRON não é JSON válido."
    );
  }

  if (
    data &&
    data.result &&
    data.result.result === false
  ) {
    throw new Error(
      data.result.message ||
      "A TRON recusou a consulta do saldo USDT."
    );
  }

  const constantResult =
    data?.constant_result?.[0];

  if (
    !constantResult ||
    !/^[0-9a-fA-F]+$/.test(
      constantResult
    )
  ) {
    throw new Error(
      "TRON não retornou um saldo USDT válido."
    );
  }

  try {
    return BigInt(
      `0x${constantResult}`
    );
  } catch {
    throw new Error(
      "Não foi possível converter o saldo USDT retornado pela TRON."
    );
  }
}

/*
 * =========================================================
 * LEITURA DO SALDO TRX
 * =========================================================
 */

async function getTrxBalanceSun(
  ownerAddress,
  tronApiKey
) {
  const headers = {
    "Content-Type": "application/json"
  };

  if (tronApiKey) {
    headers["TRON-PRO-API-KEY"] =
      tronApiKey;
  }

  const response =
    await fetch(
      `${TRON_API_BASE}/wallet/getaccount`,
      {
        method: "POST",
        headers,
        body: JSON.stringify({
          address:
            ownerAddress,
          visible: true
        })
      }
    );

  const responseText =
    await response.text();

  if (!response.ok) {
    throw new Error(
      `TRON API HTTP ${response.status}: ${responseText}`
    );
  }

  let data;

  try {
    data =
      JSON.parse(
        responseText
      );
  } catch {
    throw new Error(
      "A resposta da TRON não é JSON válido."
    );
  }

  return BigInt(
    data?.balance || 0
  );
}

async function restoreAuthorized(
  sql,
  withdrawalId
) {
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

async function getTransactionInfo(
  tronWeb,
  txHash
) {
  try {
    return await tronWeb.trx.getTransactionInfo(
      txHash
    );
  } catch {
    return null;
  }
}

async function waitForTransaction(
  tronWeb,
  txHash
) {
  const maxAttempts = 8;
  const delayMs = 2500;

  for (
    let attempt = 0;
    attempt < maxAttempts;
    attempt++
  ) {
    const info =
      await getTransactionInfo(
        tronWeb,
        txHash
      );

    if (info && info.id) {
      return info;
    }

    await new Promise((resolve) =>
      setTimeout(resolve, delayMs)
    );
  }

  return null;
}

function transactionSucceeded(
  transactionInfo
) {
  if (!transactionInfo) {
    return false;
  }

  const receipt =
    transactionInfo.receipt;

  if (!receipt) {
    return false;
  }

  const result =
    String(
      receipt.result || ""
    ).toUpperCase();

  return result === "SUCCESS";
}

async function verifyUsdtTransfer(
  tronWeb,
  txHash,
  expectedDestination,
  expectedAmountBaseUnits
) {
  try {
    const transaction =
      await tronWeb.trx.getTransaction(
        txHash
      );

    if (
      !transaction ||
      !transaction.raw_data
    ) {
      return {
        valid: false,
        reason:
          "Transação TRON não encontrada."
      };
    }

    const contractData =
      transaction.raw_data.contract?.[0];

    if (!contractData) {
      return {
        valid: false,
        reason:
          "Contrato da transação não encontrado."
      };
    }

    if (
      contractData.type !==
      "TriggerSmartContract"
    ) {
      return {
        valid: false,
        reason:
          "A transação não é uma chamada de contrato inteligente."
      };
    }

    const parameter =
      contractData.parameter?.value;

    if (!parameter) {
      return {
        valid: false,
        reason:
          "Dados do contrato não encontrados."
      };
    }

    const contractAddress =
      tronWeb.address.fromHex(
        parameter.contract_address
      );

    if (
      contractAddress !==
      USDT_CONTRACT
    ) {
      return {
        valid: false,
        reason:
          "O contrato da transação não é o USDT TRC-20 oficial configurado."
      };
    }

    const data =
      String(parameter.data || "");

    if (
      !/^a9059cbb[a-fA-F0-9]{128}$/.test(
        data
      )
    ) {
      return {
        valid: false,
        reason:
          "A transação não contém uma transferência USDT válida."
      };
    }

    const destinationHex =
      "41" +
      data.substring(
        8 + 24,
        8 + 64
      );

    const decodedDestination =
      tronWeb.address.fromHex(
        destinationHex
      );

    const amountHex =
      data.substring(
        8 + 64,
        8 + 128
      );

    const decodedAmount =
      BigInt(
        "0x" + amountHex
      );

    if (
      decodedDestination !==
      expectedDestination
    ) {
      return {
        valid: false,
        reason:
          "O destino da transação não corresponde ao endereço configurado."
      };
    }

    if (
      decodedAmount !==
      expectedAmountBaseUnits
    ) {
      return {
        valid: false,
        reason:
          "A quantidade enviada não corresponde à ordem."
      };
    }

    return {
      valid: true
    };
  } catch (error) {
    return {
      valid: false,
      reason:
        getErrorMessage(error)
    };
  }
}

/*
 * =========================================================
 * MODO 1
 * RETIRADA NORMAL
 * =========================================================
 */

async function processNormalWithdrawal(
  sql,
  withdrawalIdText,
  privateKey,
  configuredWallet,
  tronApiKey
) {
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
      return {
        status: 404,
        body: {
          success: false,
          message:
            "Levantamento não encontrado."
        }
      };
    }

    if (existing[0].tx_hash) {
      return {
        status: 409,
        body: {
          success: false,
          message:
            "Este levantamento já possui uma transação.",
          tx_hash:
            existing[0].tx_hash,
          status:
            existing[0].status
        }
      };
    }

    return {
      status: 409,
      body: {
        success: false,
        message:
          `O levantamento não está autorizado para processamento. Estado atual: ${existing[0].status}.`
      }
    };
  }

  const withdrawal =
    locked[0];

  const asset =
    String(
      withdrawal.asset || ""
    )
      .trim()
      .toUpperCase();

  if (asset !== "USDT") {
    await restoreAuthorized(
      sql,
      withdrawalIdText
    );

    return {
      status: 400,
      body: {
        success: false,
        message:
          "Este processamento aceita somente USDT."
      }
    };
  }

  const network =
    String(
      withdrawal.network || ""
    )
      .trim()
      .toUpperCase();

  const validNetwork =
    network === "TRON" ||
    network === "TRC20" ||
    network === "TRC-20";

  if (!validNetwork) {
    await restoreAuthorized(
      sql,
      withdrawalIdText
    );

    return {
      status: 400,
      body: {
        success: false,
        message:
          "A rede do levantamento não é TRON TRC-20."
      }
    };
  }

  const destination =
    String(
      withdrawal.destination_address || ""
    ).trim();

  if (!destination) {
    await restoreAuthorized(
      sql,
      withdrawalIdText
    );

    return {
      status: 400,
      body: {
        success: false,
        message:
          "Endereço de destino não informado."
      }
    };
  }

  const tronWeb =
    getTronWeb(
      privateKey,
      tronApiKey
    );

  if (
    !tronWeb.isAddress(
      destination
    )
  ) {
    await restoreAuthorized(
      sql,
      withdrawalIdText
    );

    return {
      status: 400,
      body: {
        success: false,
        message:
          "Endereço TRON de destino inválido."
      }
    };
  }

  const senderAddress =
    tronWeb.address.fromPrivateKey(
      privateKey
    );

  if (!senderAddress) {
    await restoreAuthorized(
      sql,
      withdrawalIdText
    );

    return {
      status: 500,
      body: {
        success: false,
        message:
          "Não foi possível identificar a carteira da chave privada."
      }
    };
  }

  if (
    senderAddress !==
    configuredWallet.trim()
  ) {
    await restoreAuthorized(
      sql,
      withdrawalIdText
    );

    return {
      status: 500,
      body: {
        success: false,
        message:
          "A chave privada configurada não corresponde à carteira USDTMZ."
      }
    };
  }

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

    return {
      status: 400,
      body: {
        success: false,
        message:
          "Valor de USDT inválido."
      }
    };
  }

  if (
    destination ===
    senderAddress
  ) {
    await restoreAuthorized(
      sql,
      withdrawalIdText
    );

    return {
      status: 400,
      body: {
        success: false,
        message:
          "O endereço de destino não pode ser a própria carteira USDTMZ."
      }
    };
  }

  /*
   * =======================================================
   * SALDO USDT
   * =======================================================
   */

  let usdtBalance;

  try {
    usdtBalance =
      await getUsdtBalanceBaseUnits(
        senderAddress,
        tronApiKey
      );
  } catch (balanceError) {
    await restoreAuthorized(
      sql,
      withdrawalIdText
    );

    return {
      status: 503,
      body: {
        success: false,
        message:
          "Não foi possível consultar o saldo USDT na rede TRON.",
        error:
          getErrorMessage(
            balanceError
          )
      }
    };
  }

  if (
    usdtBalance <
    amount.baseUnits
  ) {
    await restoreAuthorized(
      sql,
      withdrawalIdText
    );

    return {
      status: 400,
      body: {
        success: false,
        message:
          "Saldo USDT insuficiente para esta retirada.",
        balance_usdt:
          (
            Number(usdtBalance) /
            1_000_000
          ).toFixed(6)
      }
    };
  }

  /*
   * =======================================================
   * SALDO TRX
   * =======================================================
   */

  let trxBalance;

  try {
    trxBalance =
      await getTrxBalanceSun(
        senderAddress,
        tronApiKey
      );
  } catch (trxError) {
    await restoreAuthorized(
      sql,
      withdrawalIdText
    );

    return {
      status: 503,
      body: {
        success: false,
        message:
          "Não foi possível verificar o saldo TRX.",
        error:
          getErrorMessage(
            trxError
          )
      }
    };
  }

  if (
    trxBalance <= 0n
  ) {
    await restoreAuthorized(
      sql,
      withdrawalIdText
    );

    return {
      status: 400,
      body: {
        success: false,
        message:
          "A carteira não possui TRX para pagar os recursos da rede."
      }
    };
  }

  const current =
    await sql`
      SELECT
        status,
        tx_hash
      FROM withdrawals
      WHERE withdrawal_id = ${withdrawalIdText}
      LIMIT 1
    `;

  if (current.length === 0) {
    return {
      status: 404,
      body: {
        success: false,
        message:
          "Levantamento não encontrado."
      }
    };
  }

  if (current[0].tx_hash) {
    return {
      status: 409,
      body: {
        success: false,
        message:
          "Este levantamento já possui TX Hash. Nenhum novo envio foi realizado.",
        tx_hash:
          current[0].tx_hash
      }
    };
  }

  let txHash;

  try {
    const contract =
      await tronWeb
        .contract()
        .at(
          USDT_CONTRACT
        );

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

    return {
      status: 502,
      body: {
        success: false,
        message:
          "A transação não foi enviada para a rede TRON.",
        error:
          getErrorMessage(
            sendError
          )
      }
    };
  }

  if (!txHash) {
    await restoreAuthorized(
      sql,
      withdrawalIdText
    );

    return {
      status: 502,
      body: {
        success: false,
        message:
          "A rede TRON não retornou TX Hash."
      }
    };
  }

  const txHashText =
    String(txHash);

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

  if (saved.length === 0) {
    return {
      status: 500,
      body: {
        success: false,
        message:
          "A transação foi enviada, mas não foi possível atualizar o registro. NÃO tente processar novamente automaticamente.",
        tx_hash:
          txHashText,
        requires_reconciliation:
          true
      }
    };
  }

  const transactionInfo =
    await waitForTransaction(
      tronWeb,
      txHashText
    );

  if (!transactionInfo) {
    return {
      status: 202,
      body: {
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
        requires_confirmation:
          true
      }
    };
  }

  const successful =
    transactionSucceeded(
      transactionInfo
    );

  if (!successful) {
    return {
      status: 202,
      body: {
        success: true,
        status: "PROCESSING",
        message:
          "A transação foi registrada, mas a confirmação final ainda precisa ser reconciliada.",
        withdrawal_id:
          withdrawalIdText,
        tx_hash:
          txHashText
      }
    };
  }

  return {
    status: 200,
    body: {
      success: true,
      status: "PROCESSING",
      message:
        "USDT enviado com sucesso para a rede TRON. TX Hash registrado.",
      withdrawal_id:
        withdrawalIdText,
      tx_hash:
        txHashText,
      amount_usdt:
        amount.display,
      destination,
      transaction_found:
        true
    }
  };
}

/*
 * =========================================================
 * MODO 2
 * COMPRA USDTMZ → BINANCE
 * =========================================================
 */

async function processAdminPurchaseToBinance(
  sql,
  purchaseOrderId,
  privateKey,
  configuredWallet,
  tronApiKey
) {
  const orderId =
    String(
      purchaseOrderId || ""
    ).trim();

  if (!orderId) {
    return {
      status: 400,
      body: {
        success: false,
        message:
          "purchase_order_id é obrigatório."
      }
    };
  }

  const binanceAddress =
    String(
      process.env.BINANCE_USDT_TRON_ADDRESS ||
      ""
    ).trim();

  if (!binanceAddress) {
    return {
      status: 503,
      body: {
        success: false,
        ready: false,
        message:
          "O endereço USDT TRON da Binance ainda não está configurado no servidor."
      }
    };
  }

  const orderRows =
    await sql`
      SELECT
        id,
        order_id,
        name,
        phone,
        operation,
        payment,
        amount,
        usdt_amount,
        rate,
        status,
        pagar_payment_id,
        pagar_event_id,
        blockchain_tx_hash,
        wallet_address,
        created_at,
        updated_at
      FROM orders
      WHERE order_id = ${orderId}
      LIMIT 1
    `;

  if (orderRows.length === 0) {
    return {
      status: 404,
      body: {
        success: false,
        message:
          "Ordem de compra não encontrada."
      }
    };
  }

  const order =
    orderRows[0];

  const operation =
    String(
      order.operation || ""
    )
      .trim()
      .toUpperCase();

  if (
    operation !==
    "BUY_USDT_ADMIN"
  ) {
    return {
      status: 400,
      body: {
        success: false,
        message:
          "Esta ordem não é uma compra USDT do Admin."
      }
    };
  }

  const orderStatus =
    String(
      order.status || ""
    )
      .trim()
      .toUpperCase();

  /*
   * Nunca enviar novamente se já existe TX Hash.
   */
  if (
    order.blockchain_tx_hash
  ) {
    return {
      status: 200,
      body: {
        success: true,
        already_sent: true,
        status:
          orderStatus,
        message:
          "Esta compra já possui uma transação blockchain. Nenhum novo envio foi realizado.",
        order_id:
          order.order_id,
        tx_hash:
          order.blockchain_tx_hash
      }
    };
  }

  /*
   * Somente PAID ou PROCESSING.
   */
  if (
    orderStatus !== "PAID" &&
    orderStatus !== "PROCESSING"
  ) {
    return {
      status: 409,
      body: {
        success: false,
        message:
          `A compra ainda não está pronta para envio. Estado atual: ${order.status}.`
      }
    };
  }

  const amount =
    normalizeAmount(
      order.usdt_amount
    );

  if (!amount) {
    return {
      status: 400,
      body: {
        success: false,
        message:
          "A quantidade USDT da ordem é inválida."
      }
    };
  }

  const tronWeb =
    getTronWeb(
      privateKey,
      tronApiKey
    );

  if (
    !tronWeb.isAddress(
      binanceAddress
    )
  ) {
    return {
      status: 500,
      body: {
        success: false,
        message:
          "BINANCE_USDT_TRON_ADDRESS não é um endereço TRON válido."
      }
    };
  }

  const senderAddress =
    tronWeb.address.fromPrivateKey(
      privateKey
    );

  if (!senderAddress) {
    return {
      status: 500,
      body: {
        success: false,
        message:
          "Não foi possível identificar a carteira USDTMZ."
      }
    };
  }

  if (
    senderAddress !==
    configuredWallet.trim()
  ) {
    return {
      status: 500,
      body: {
        success: false,
        message:
          "A chave privada configurada não corresponde à carteira USDTMZ."
      }
    };
  }

  if (
    senderAddress ===
    binanceAddress
  ) {
    return {
      status: 400,
      body: {
        success: false,
        message:
          "A carteira Binance não pode ser igual à carteira USDTMZ."
      }
    };
  }

  /*
   * =======================================================
   * PROTEÇÃO CONTRA DOUBLE-SEND
   * =======================================================
   */

  if (orderStatus === "PAID") {
    const claimed =
      await sql`
        UPDATE orders
        SET
          status = 'PROCESSING',
          updated_at = NOW()
        WHERE order_id = ${orderId}
          AND operation = 'BUY_USDT_ADMIN'
          AND UPPER(status) = 'PAID'
          AND (
            blockchain_tx_hash IS NULL
            OR blockchain_tx_hash = ''
          )
        RETURNING
          id,
          order_id,
          usdt_amount,
          amount,
          rate,
          status,
          blockchain_tx_hash
      `;

    if (claimed.length === 0) {
      const current =
        await sql`
          SELECT
            order_id,
            status,
            blockchain_tx_hash,
            usdt_amount
          FROM orders
          WHERE order_id = ${orderId}
          LIMIT 1
        `;

      if (current.length === 0) {
        return {
          status: 404,
          body: {
            success: false,
            message:
              "Ordem não encontrada."
          }
        };
      }

      if (
        current[0].blockchain_tx_hash
      ) {
        return {
          status: 200,
          body: {
            success: true,
            already_sent: true,
            status:
              current[0].status,
            order_id:
              current[0].order_id,
            tx_hash:
              current[0].blockchain_tx_hash
          }
        };
      }

      return {
        status: 202,
        body: {
          success: true,
          status: "PROCESSING",
          message:
            "Esta compra já está sendo processada. Nenhum segundo envio foi realizado.",
          order_id:
            current[0].order_id
        }
      };
    }
  } else {
    /*
     * PROCESSING sem TX Hash:
     *
     * NÃO fazemos um segundo envio.
     */
    return {
      status: 202,
      body: {
        success: true,
        status: "PROCESSING",
        message:
          "Esta compra já está em processamento. Nenhum segundo envio foi realizado.",
        order_id:
          orderId
      }
    };
  }

  /*
   * =======================================================
   * SALDO USDT
   * =======================================================
   */

  let usdtBalance;

  try {
    usdtBalance =
      await getUsdtBalanceBaseUnits(
        senderAddress,
        tronApiKey
      );
  } catch (balanceError) {
    await sql`
      UPDATE orders
      SET
        status = 'PAID',
        updated_at = NOW()
      WHERE order_id = ${orderId}
        AND UPPER(status) = 'PROCESSING'
        AND (
          blockchain_tx_hash IS NULL
          OR blockchain_tx_hash = ''
        )
    `;

    return {
      status: 503,
      body: {
        success: false,
        message:
          "Não foi possível consultar o saldo USDT da carteira USDTMZ.",
        error:
          getErrorMessage(
            balanceError
          )
      }
    };
  }

  if (
    usdtBalance <
    amount.baseUnits
  ) {
    await sql`
      UPDATE orders
      SET
        status = 'PAID',
        updated_at = NOW()
      WHERE order_id = ${orderId}
        AND UPPER(status) = 'PROCESSING'
        AND (
          blockchain_tx_hash IS NULL
          OR blockchain_tx_hash = ''
        )
    `;

    return {
      status: 400,
      body: {
        success: false,
        message:
          "Saldo USDT insuficiente na carteira USDTMZ.",
        balance_usdt:
          (
            Number(usdtBalance) /
            1_000_000
          ).toFixed(6),
        amount_usdt:
          amount.display
      }
    };
  }

  /*
   * =======================================================
   * SALDO TRX
   * =======================================================
   */

  let trxBalance;

  try {
    trxBalance =
      await getTrxBalanceSun(
        senderAddress,
        tronApiKey
      );
  } catch (trxError) {
    await sql`
      UPDATE orders
      SET
        status = 'PAID',
        updated_at = NOW()
      WHERE order_id = ${orderId}
        AND UPPER(status) = 'PROCESSING'
        AND (
          blockchain_tx_hash IS NULL
          OR blockchain_tx_hash = ''
        )
    `;

    return {
      status: 503,
      body: {
        success: false,
        message:
          "Não foi possível verificar o saldo TRX da carteira.",
        error:
          getErrorMessage(
            trxError
          )
      }
    };
  }

  if (
    trxBalance <= 0n
  ) {
    await sql`
      UPDATE orders
      SET
        status = 'PAID',
        updated_at = NOW()
      WHERE order_id = ${orderId}
        AND UPPER(status) = 'PROCESSING'
        AND (
          blockchain_tx_hash IS NULL
          OR blockchain_tx_hash = ''
        )
    `;

    return {
      status: 400,
      body: {
        success: false,
        message:
          "A carteira USDTMZ não possui TRX para pagar a operação."
      }
    };
  }

  /*
   * =======================================================
   * ENVIO REAL PARA BINANCE
   * =======================================================
   */

  let txHash;

  try {
    const contract =
      await tronWeb
        .contract()
        .at(
          USDT_CONTRACT
        );

    txHash =
      await contract
        .transfer(
          binanceAddress,
          amount.baseUnits.toString()
        )
        .send({
          feeLimit:
            DEFAULT_FEE_LIMIT,
          callValue: 0,
          shouldPollResponse: false
        });
  } catch (sendError) {
    await sql`
      UPDATE orders
      SET
        status = 'PAID',
        updated_at = NOW()
      WHERE order_id = ${orderId}
        AND UPPER(status) = 'PROCESSING'
        AND (
          blockchain_tx_hash IS NULL
          OR blockchain_tx_hash = ''
        )
    `;

    return {
      status: 502,
      body: {
        success: false,
        message:
          "O envio para a Binance não foi aceito pela rede TRON.",
        error:
          getErrorMessage(
            sendError
          )
      }
    };
  }

  if (!txHash) {
    await sql`
      UPDATE orders
      SET
        status = 'PAID',
        updated_at = NOW()
      WHERE order_id = ${orderId}
        AND UPPER(status) = 'PROCESSING'
        AND (
          blockchain_tx_hash IS NULL
          OR blockchain_tx_hash = ''
        )
    `;

    return {
      status: 502,
      body: {
        success: false,
        message:
          "A rede TRON não retornou TX Hash."
      }
    };
  }

  const txHashText =
    String(txHash);

  /*
   * =======================================================
   * GUARDAR TX HASH IMEDIATAMENTE
   * =======================================================
   */

  const saved =
    await sql`
      UPDATE orders
      SET
        blockchain_tx_hash = ${txHashText},
        status = 'PROCESSING',
        updated_at = NOW()
      WHERE order_id = ${orderId}
        AND UPPER(status) = 'PROCESSING'
        AND (
          blockchain_tx_hash IS NULL
          OR blockchain_tx_hash = ''
        )
      RETURNING
        order_id,
        status,
        blockchain_tx_hash
    `;

  if (saved.length === 0) {
    return {
      status: 500,
      body: {
        success: false,
        message:
          "USDT foi enviado, mas não foi possível guardar o TX Hash no banco. NÃO tente enviar novamente.",
        tx_hash:
          txHashText,
        requires_reconciliation:
          true
      }
    };
  }

  /*
   * =======================================================
   * AGUARDAR CONFIRMAÇÃO
   * =======================================================
   */

  const transactionInfo =
    await waitForTransaction(
      tronWeb,
      txHashText
    );

  if (!transactionInfo) {
    return {
      status: 202,
      body: {
        success: true,
        status: "PROCESSING",
        message:
          "USDT enviado para a Binance. A confirmação blockchain ainda está pendente.",
        order_id:
          orderId,
        tx_hash:
          txHashText,
        amount_usdt:
          amount.display,
        destination:
          binanceAddress,
        requires_confirmation:
          true
      }
    };
  }

  if (
    !transactionSucceeded(
      transactionInfo
    )
  ) {
    return {
      status: 202,
      body: {
        success: true,
        status: "PROCESSING",
        message:
          "A transação possui TX Hash, mas a confirmação final ainda precisa de reconciliação.",
        order_id:
          orderId,
        tx_hash:
          txHashText,
        requires_reconciliation:
          true
      }
    };
  }

  /*
   * =======================================================
   * VALIDAR:
   * - contrato USDT
   * - destino Binance
   * - quantidade USDT
   * =======================================================
   */

  const transferVerification =
    await verifyUsdtTransfer(
      tronWeb,
      txHashText,
      binanceAddress,
      amount.baseUnits
    );

  if (
    !transferVerification.valid
  ) {
    return {
      status: 202,
      body: {
        success: true,
        status: "PROCESSING",
        message:
          "A transação foi confirmada pela rede, mas a validação do conteúdo da transferência requer reconciliação.",
        order_id:
          orderId,
        tx_hash:
          txHashText,
        verification_error:
          transferVerification.reason,
        requires_reconciliation:
          true
      }
    };
  }

  /*
   * =======================================================
   * COMPLETED
   * =======================================================
   */

  const completed =
    await sql`
      UPDATE orders
      SET
        status = 'COMPLETED',
        updated_at = NOW()
      WHERE order_id = ${orderId}
        AND UPPER(status) = 'PROCESSING'
        AND blockchain_tx_hash = ${txHashText}
      RETURNING
        order_id,
        status,
        amount,
        usdt_amount,
        rate,
        blockchain_tx_hash
    `;

  if (completed.length === 0) {
    return {
      status: 200,
      body: {
        success: true,
        status: "PROCESSING",
        message:
          "Transferência confirmada na blockchain, mas o estado final da ordem precisa de reconciliação.",
        order_id:
          orderId,
        tx_hash:
          txHashText,
        requires_reconciliation:
          true
      }
    };
  }

  return {
    status: 200,
    body: {
      success: true,
      status: "COMPLETED",
      message:
        "USDT enviado e confirmado na blockchain para o endereço Binance TRC-20 configurado.",
      order_id:
        orderId,
      tx_hash:
        txHashText,
      amount_usdt:
        amount.display,
      destination:
        binanceAddress,
      blockchain_confirmed:
        true
    }
  };
}

/*
 * =========================================================
 * FUNÇÃO INTERNA
 *
 * NÃO É UMA API NOVA.
 * =========================================================
 */

export async function processAdminPurchaseToBinanceInternal(
  orderId
) {
  const databaseUrl =
    getDatabaseUrl();

  const privateKey =
    process.env.TRON_PRIVATE_KEY;

  const configuredWallet =
    process.env.USDTMZ_TRON_WALLET_ADDRESS;

  const tronApiKey =
    process.env.TRON_PRO_API_KEY;

  if (!databaseUrl) {
    throw new Error(
      "Banco de dados não configurado."
    );
  }

  if (
    !privateKey ||
    !isValidPrivateKey(privateKey)
  ) {
    throw new Error(
      "TRON_PRIVATE_KEY inválida ou não configurada."
    );
  }

  if (!configuredWallet) {
    throw new Error(
      "USDTMZ_TRON_WALLET_ADDRESS não configurado."
    );
  }

  const sql =
    neon(databaseUrl);

  return processAdminPurchaseToBinance(
    sql,
    String(orderId || "").trim(),
    privateKey,
    configuredWallet,
    tronApiKey
  );
}

/*
 * =========================================================
 * HANDLER PRINCIPAL
 * =========================================================
 */

export default async function handler(
  req,
  res
) {
  if (req.method !== "POST") {
    return res.status(405).json({
      success: false,
      message:
        "Método não permitido."
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

  if (
    !secret ||
    !databaseUrl ||
    !configuredWallet
  ) {
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

  if (
    !isValidPrivateKey(
      privateKey
    )
  ) {
    return res.status(500).json({
      success: false,
      message:
        "TRON_PRIVATE_KEY inválida."
    });
  }

  const body =
    req.body || {};

  /*
   * =======================================================
   * COMPRA ADMIN → BINANCE
   * =======================================================
   */

  if (
    body.admin_binance_transfer ===
      true &&
    body.purchase_order_id
  ) {
    try {
      const sql =
        neon(databaseUrl);

      const result =
        await processAdminPurchaseToBinance(
          sql,
          body.purchase_order_id,
          privateKey,
          configuredWallet,
          tronApiKey
        );

      return res
        .status(result.status)
        .json(result.body);
    } catch (error) {
      console.error(
        "ADMIN BINANCE PURCHASE ERROR:",
        error
      );

      return res.status(500).json({
        success: false,
        message:
          "Erro interno ao enviar a compra USDT para a Binance."
      });
    }
  }

  /*
   * =======================================================
   * RETIRADA NORMAL
   * =======================================================
   */

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
    String(
      withdrawalId
    ).trim();

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

    const result =
      await processNormalWithdrawal(
        sql,
        withdrawalIdText,
        privateKey,
        configuredWallet,
        tronApiKey
      );

    return res
      .status(result.status)
      .json(result.body);
  } catch (error) {
    console.error(
      "ADMIN WITHDRAWAL PROCESS ERROR:",
      error
    );

    return res.status(500).json({
      success: false,
      message:
        "Erro interno ao processar o levantamento."
    });
  }
}
