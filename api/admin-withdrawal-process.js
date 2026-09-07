import { neon } from "@neondatabase/serverless";
import { createHmac, timingSafeEqual } from "node:crypto";
import { TronWeb } from "tronweb";

const COOKIE_NAME = "usdtmz_admin_session";

const USDT_CONTRACT =
  "TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t";

const USDT_DECIMALS = 6;

const TRON_API_BASE =
  "https://api.trongrid.io";

const DEFAULT_FEE_LIMIT =
  100_000_000;

/* =========================================================
   SEGURANÇA
   ========================================================= */

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

  const expectedSignature = createHmac(
    "sha256",
    secret
  )
    .update(data)
    .digest("base64url");

  if (!safeCompare(signature, expectedSignature)) {
    return null;
  }

  try {
    const payload = JSON.parse(
      Buffer.from(data, "base64url").toString("utf8")
    );

    if (
      !payload.exp ||
      Date.now() > Number(payload.exp)
    ) {
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
  const cookies =
    req.headers.cookie || "";

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

/* =========================================================
   DATABASE
   ========================================================= */

function getDatabaseUrl() {
  return (
    process.env.URL_DO_BANCO_DE_DADOS ||
    process.env.POSTGRES_URL ||
    process.env.DATABASE_URL ||
    process.env.POSTGRES_URL_NON_POOLING ||
    process.env.DATABASE_URL_UNPOOLED
  );
}

/* =========================================================
   TRON
   ========================================================= */

function isValidPrivateKey(value) {
  return /^[0-9a-fA-F]{64}$/.test(
    String(value || "")
  );
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

/* =========================================================
   VALOR USDT
   ========================================================= */

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

  const decimal = (
    parts[1] || ""
  ).padEnd(
    USDT_DECIMALS,
    "0"
  );

  const baseUnits =
    BigInt(whole) *
      1_000_000n +
    BigInt(decimal);

  if (baseUnits <= 0n) {
    return null;
  }

  return {
    text,
    baseUnits,
    display: (
      Number(baseUnits) /
      1_000_000
    ).toFixed(6)
  };
}

/* =========================================================
   SALDO USDT
   ========================================================= */

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

  if (!tronWeb.isAddress(ownerAddress)) {
    throw new Error(
      "Endereço da carteira USDTMZ inválido."
    );
  }

  const ownerHex =
    tronWeb.address
      .toHex(ownerAddress)
      .replace(/^41/, "");

  const parameter =
    ownerHex.padStart(
      64,
      "0"
    );

  const response =
    await fetch(
      `${TRON_API_BASE}/wallet/triggerconstantcontract`,
      {
        method: "POST",
        headers: {
          "Content-Type":
            "application/json",
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

  const text =
    await response.text();

  if (!response.ok) {
    throw new Error(
      `TRON API HTTP ${response.status}: ${text}`
    );
  }

  let data;

  try {
    data = JSON.parse(text);
  } catch {
    throw new Error(
      "Resposta inválida da TRON."
    );
  }

  const result =
    data?.constant_result?.[0];

  if (
    !result ||
    !/^[0-9a-fA-F]+$/.test(result)
  ) {
    throw new Error(
      "TRON não retornou saldo USDT válido."
    );
  }

  return BigInt(`0x${result}`);
}

/* =========================================================
   SALDO TRX
   ========================================================= */

async function getTrxBalanceSun(
  ownerAddress,
  tronApiKey
) {
  const headers = {
    "Content-Type":
      "application/json"
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

  const text =
    await response.text();

  if (!response.ok) {
    throw new Error(
      `TRON API HTTP ${response.status}: ${text}`
    );
  }

  let data;

  try {
    data = JSON.parse(text);
  } catch {
    throw new Error(
      "Resposta inválida da TRON."
    );
  }

  return BigInt(
    data?.balance || 0
  );
}

/* =========================================================
   TRANSAÇÃO
   ========================================================= */

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

    await new Promise(
      (resolve) =>
        setTimeout(
          resolve,
          delayMs
        )
    );
  }

  return null;
}

function transactionSucceeded(info) {
  if (!info) {
    return false;
  }

  if (
    info.receipt &&
    info.receipt.result
  ) {
    return (
      String(
        info.receipt.result
      ).toUpperCase() ===
      "SUCCESS"
    );
  }

  if (
    info.receipt &&
    info.receipt.result ===
      undefined
  ) {
    return true;
  }

  return false;
}

/* =========================================================
   VALIDAR TRANSFERÊNCIA USDT
   ========================================================= */

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

    const contract =
      transaction.raw_data
        .contract?.[0];

    if (!contract) {
      return {
        valid: false,
        reason:
          "Contrato da transação não encontrado."
      };
    }

    if (
      contract.type !==
      "TriggerSmartContract"
    ) {
      return {
        valid: false,
        reason:
          "A transação não é uma chamada de contrato."
      };
    }

    const parameter =
      contract.parameter?.value;

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
          "Contrato USDT incorreto."
      };
    }

    const data =
      String(
        parameter.data || ""
      );

    if (
      !/^a9059cbb[a-fA-F0-9]{128}$/.test(
        data
      )
    ) {
      return {
        valid: false,
        reason:
          "Transferência USDT inválida."
      };
    }

    const destinationHex =
      "41" +
      data.substring(
        8 + 24,
        8 + 64
      );

    const destination =
      tronWeb.address.fromHex(
        destinationHex
      );

    const amountHex =
      data.substring(
        8 + 64,
        8 + 128
      );

    const amount =
      BigInt(
        "0x" + amountHex
      );

    if (
      destination !==
      expectedDestination
    ) {
      return {
        valid: false,
        reason:
          "Destino incorreto."
      };
    }

    if (
      amount !==
      expectedAmountBaseUnits
    ) {
      return {
        valid: false,
        reason:
          "Quantidade USDT incorreta."
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

/* =========================================================
   RETIRADA NORMAL
   ========================================================= */

async function processNormalWithdrawal(
  sql,
  withdrawalId,
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
      WHERE withdrawal_id =
        ${withdrawalId}
        AND UPPER(status) =
          'AUTHORIZED'
        AND (
          tx_hash IS NULL
          OR tx_hash = ''
        )
      RETURNING *
    `;

  if (locked.length === 0) {
    const current =
      await sql`
        SELECT
          withdrawal_id,
          status,
          tx_hash
        FROM withdrawals
        WHERE withdrawal_id =
          ${withdrawalId}
        LIMIT 1
      `;

    if (!current.length) {
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
            "Este levantamento já possui TX Hash.",
          tx_hash:
            current[0].tx_hash
        }
      };
    }

    return {
      status: 409,
      body: {
        success: false,
        message:
          `Estado atual: ${current[0].status}.`
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

  const network =
    String(
      withdrawal.network || ""
    )
      .trim()
      .toUpperCase();

  if (asset !== "USDT") {
    return {
      status: 400,
      body: {
        success: false,
        message:
          "Somente USDT pode ser processado."
      }
    };
  }

  if (
    !["TRON", "TRC20", "TRC-20"]
      .includes(network)
  ) {
    return {
      status: 400,
      body: {
        success: false,
        message:
          "A rede deve ser TRON TRC-20."
      }
    };
  }

  const destination =
    String(
      withdrawal.destination_address ||
      ""
    ).trim();

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
    return {
      status: 400,
      body: {
        success: false,
        message:
          "Endereço TRON inválido."
      }
    };
  }

  const sender =
    tronWeb.address.fromPrivateKey(
      privateKey
    );

  if (
    sender !==
    configuredWallet.trim()
  ) {
    return {
      status: 500,
      body: {
        success: false,
        message:
          "A chave privada não corresponde à carteira USDTMZ."
      }
    };
  }

  if (sender === destination) {
    return {
      status: 400,
      body: {
        success: false,
        message:
          "Destino não pode ser a carteira USDTMZ."
      }
    };
  }

  const amount =
    normalizeAmount(
      withdrawal.amount_to_send ??
      withdrawal.amount ??
      withdrawal.amount_requested
    );

  if (!amount) {
    return {
      status: 400,
      body: {
        success: false,
        message:
          "Valor USDT inválido."
      }
    };
  }

  const balance =
    await getUsdtBalanceBaseUnits(
      sender,
      tronApiKey
    );

  if (
    balance <
    amount.baseUnits
  ) {
    return {
      status: 400,
      body: {
        success: false,
        message:
          "Saldo USDT insuficiente."
      }
    };
  }

  const trx =
    await getTrxBalanceSun(
      sender,
      tronApiKey
    );

  if (trx <= 0n) {
    return {
      status: 400,
      body: {
        success: false,
        message:
          "Saldo TRX insuficiente."
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
          shouldPollResponse:
            false
        });
  } catch (error) {
    /*
     * IMPORTANTE:
     * Nunca voltar automaticamente
     * para AUTHORIZED depois de uma
     * tentativa de broadcast.
     *
     * Mantemos PROCESSING para
     * reconciliação.
     */
    return {
      status: 502,
      body: {
        success: false,
        status:
          "PROCESSING",
        message:
          "Não foi possível confirmar o resultado do envio. A operação ficou em PROCESSING para reconciliação.",
        error:
          getErrorMessage(error),
        requires_reconciliation:
          true
      }
    };
  }

  if (!txHash) {
    return {
      status: 502,
      body: {
        success: false,
        status:
          "PROCESSING",
        message:
          "A TRON não retornou TX Hash. A operação requer reconciliação.",
        requires_reconciliation:
          true
      }
    };
  }

  const hash =
    String(txHash);

  const saved =
    await sql`
      UPDATE withdrawals
      SET
        tx_hash = ${hash},
        status = 'PROCESSING',
        updated_at = NOW()
      WHERE withdrawal_id =
        ${withdrawalId}
        AND UPPER(status) =
          'PROCESSING'
        AND (
          tx_hash IS NULL
          OR tx_hash = ''
        )
      RETURNING
        withdrawal_id,
        status,
        tx_hash
    `;

  if (!saved.length) {
    return {
      status: 500,
      body: {
        success: false,
        message:
          "USDT foi enviado, mas o TX Hash não pôde ser salvo. NÃO envie novamente.",
        tx_hash: hash,
        requires_reconciliation:
          true
      }
    };
  }

  const info =
    await waitForTransaction(
      tronWeb,
      hash
    );

  return {
    status: 202,
    body: {
      success: true,
      status:
        "PROCESSING",
      message:
        info
          ? "TX Hash registrado. A confirmação final permanece em PROCESSING."
          : "USDT enviado para a rede TRON. Confirmação pendente.",
      withdrawal_id:
        withdrawalId,
      tx_hash: hash,
      amount_usdt:
        amount.display,
      destination,
      requires_confirmation:
        true
    }
  };
}

/* =========================================================
   COMPRA ADMIN → BINANCE
   ========================================================= */

async function processAdminPurchaseToBinance(
  sql,
  orderId,
  privateKey,
  configuredWallet,
  tronApiKey
) {
  const id =
    String(orderId || "").trim();

  if (!id) {
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
          "O endereço USDT TRON da Binance não está configurado no servidor."
      }
    };
  }

  const rows =
    await sql`
      SELECT
        id,
        order_id,
        operation,
        amount,
        usdt_amount,
        rate,
        status,
        pagar_payment_id,
        pagar_event_id,
        blockchain_tx_hash,
        created_at,
        updated_at
      FROM orders
      WHERE order_id = ${id}
      LIMIT 1
    `;

  if (!rows.length) {
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
    rows[0];

  if (
    String(order.operation || "")
      .trim()
      .toUpperCase() !==
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

  /*
   * Nunca enviar novamente se
   * já existe TX Hash.
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
          order.status,
        order_id:
          id,
        tx_hash:
          order.blockchain_tx_hash
      }
    };
  }

  const orderStatus =
    String(
      order.status || ""
    )
      .trim()
      .toUpperCase();

  if (
    orderStatus !== "PAID"
  ) {
    return {
      status: 409,
      body: {
        success: false,
        message:
          `A compra ainda não está PAID. Estado atual: ${order.status}.`
      }
    };
  }

  /*
   * CLAIM ATÔMICO.
   *
   * Apenas uma execução pode
   * passar de PAID → PROCESSING.
   */
  const claimed =
    await sql`
      UPDATE orders
      SET
        status = 'PROCESSING',
        updated_at = NOW()
      WHERE order_id = ${id}
        AND operation =
          'BUY_USDT_ADMIN'
        AND UPPER(status) =
          'PAID'
        AND (
          blockchain_tx_hash IS NULL
          OR blockchain_tx_hash = ''
        )
      RETURNING
        order_id,
        usdt_amount,
        status
    `;

  if (!claimed.length) {
    const current =
      await sql`
        SELECT
          status,
          blockchain_tx_hash
        FROM orders
        WHERE order_id = ${id}
        LIMIT 1
      `;

    if (
      current[0]?.blockchain_tx_hash
    ) {
      return {
        status: 200,
        body: {
          success: true,
          already_sent: true,
          status:
            current[0].status,
          tx_hash:
            current[0]
              .blockchain_tx_hash
        }
      };
    }

    return {
      status: 202,
      body: {
        success: true,
        status:
          "PROCESSING",
        message:
          "Esta compra já está sendo processada. Nenhum segundo envio foi realizado.",
        order_id: id
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
          "Quantidade USDT inválida."
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
          "BINANCE_USDT_TRON_ADDRESS inválido."
      }
    };
  }

  const sender =
    tronWeb.address.fromPrivateKey(
      privateKey
    );

  if (
    sender !==
    configuredWallet.trim()
  ) {
    return {
      status: 500,
      body: {
        success: false,
        message:
          "A chave privada não corresponde à carteira USDTMZ."
      }
    };
  }

  if (
    sender ===
    binanceAddress
  ) {
    return {
      status: 400,
      body: {
        success: false,
        message:
          "Binance não pode ser a própria carteira USDTMZ."
      }
    };
  }

  const usdtBalance =
    await getUsdtBalanceBaseUnits(
      sender,
      tronApiKey
    );

  if (
    usdtBalance <
    amount.baseUnits
  ) {
    return {
      status: 400,
      body: {
        success: false,
        status:
          "PROCESSING",
        message:
          "Saldo USDT insuficiente. A compra permanece PROCESSING.",
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

  const trxBalance =
    await getTrxBalanceSun(
      sender,
      tronApiKey
    );

  if (trxBalance <= 0n) {
    return {
      status: 400,
      body: {
        success: false,
        status:
          "PROCESSING",
        message:
          "Saldo TRX insuficiente. A compra permanece PROCESSING."
      }
    };
  }

  /*
   * ENVIO REAL.
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
          shouldPollResponse:
            false
        });
  } catch (error) {
    /*
     * NÃO voltar para PAID.
     *
     * O resultado do broadcast pode
     * ser desconhecido.
     */
    return {
      status: 502,
      body: {
        success: false,
        status:
          "PROCESSING",
        message:
          "Não foi possível determinar com segurança o resultado do envio. A compra permanece PROCESSING.",
        error:
          getErrorMessage(error),
        requires_reconciliation:
          true
      }
    };
  }

  if (!txHash) {
    return {
      status: 502,
      body: {
        success: false,
        status:
          "PROCESSING",
        message:
          "A TRON não retornou TX Hash. A compra permanece PROCESSING para reconciliação.",
        requires_reconciliation:
          true
      }
    };
  }

  const hash =
    String(txHash);

  /*
   * SALVAR TX HASH IMEDIATAMENTE.
   */
  const saved =
    await sql`
      UPDATE orders
      SET
        blockchain_tx_hash =
          ${hash},
        status =
          'PROCESSING',
        updated_at =
          NOW()
      WHERE order_id =
        ${id}
        AND UPPER(status) =
          'PROCESSING'
        AND (
          blockchain_tx_hash IS NULL
          OR blockchain_tx_hash = ''
        )
      RETURNING
        order_id,
        status,
        blockchain_tx_hash
    `;

  if (!saved.length) {
    return {
      status: 500,
      body: {
        success: false,
        status:
          "PROCESSING",
        message:
          "USDT foi enviado, mas o TX Hash não pôde ser salvo. NÃO envie novamente.",
        tx_hash: hash,
        requires_reconciliation:
          true
      }
    };
  }

  /*
   * CONFIRMAÇÃO.
   */
  const info =
    await waitForTransaction(
      tronWeb,
      hash
    );

  if (!info) {
    return {
      status: 202,
      body: {
        success: true,
        status:
          "PROCESSING",
        message:
          "USDT enviado para Binance. Confirmação blockchain pendente.",
        order_id: id,
        tx_hash: hash,
        amount_usdt:
          amount.display,
        requires_confirmation:
          true
      }
    };
  }

  if (
    !transactionSucceeded(info)
  ) {
    return {
      status: 202,
      body: {
        success: true,
        status:
          "PROCESSING",
        message:
          "A transação possui TX Hash, mas requer reconciliação.",
        order_id: id,
        tx_hash: hash,
        requires_reconciliation:
          true
      }
    };
  }

  /*
   * VALIDAR DESTINO E VALOR.
   */
  const verification =
    await verifyUsdtTransfer(
      tronWeb,
      hash,
      binanceAddress,
      amount.baseUnits
    );

  if (!verification.valid) {
    return {
      status: 202,
      body: {
        success: true,
        status:
          "PROCESSING",
        message:
          "A blockchain confirmou a transação, mas a transferência requer reconciliação.",
        order_id: id,
        tx_hash: hash,
        verification_error:
          verification.reason,
        requires_reconciliation:
          true
      }
    };
  }

  /*
   * COMPLETED.
   */
  const completed =
    await sql`
      UPDATE orders
      SET
        status = 'COMPLETED',
        updated_at = NOW()
      WHERE order_id = ${id}
        AND UPPER(status) =
          'PROCESSING'
        AND blockchain_tx_hash =
          ${hash}
      RETURNING
        order_id,
        status,
        usdt_amount,
        blockchain_tx_hash
    `;

  if (!completed.length) {
    return {
      status: 200,
      body: {
        success: true,
        status:
          "PROCESSING",
        message:
          "Transferência confirmada, mas o estado final requer reconciliação.",
        order_id: id,
        tx_hash: hash,
        requires_reconciliation:
          true
      }
    };
  }

  return {
    status: 200,
    body: {
      success: true,
      status:
        "COMPLETED",
      message:
        "USDT enviado e confirmado na blockchain.",
      order_id: id,
      tx_hash: hash,
      amount_usdt:
        amount.display,
      blockchain_confirmed:
        true
    }
  };
}

/* =========================================================
   FUNÇÃO INTERNA
   NÃO É UMA API NOVA.
   É usada pelo criar-compra.js
   após pagamento PAID.
   ========================================================= */

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

/* =========================================================
   HANDLER PRINCIPAL
   ========================================================= */

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
        "TRON_PRIVATE_KEY ainda não está configurada."
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
   * ADMIN → BINANCE
   */
  if (
    body.admin_binance_transfer === true &&
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
          "Erro interno ao enviar USDT para Binance.",
        detail:
          getErrorMessage(error)
      });
    }
  }

  /*
   * RETIRADA NORMAL
   */
  const withdrawalId =
    String(
      body.withdrawal_id || ""
    ).trim();

  if (!withdrawalId) {
    return res.status(400).json({
      success: false,
      message:
        "withdrawal_id é obrigatório."
    });
  }

  try {
    const sql =
      neon(databaseUrl);

    const result =
      await processNormalWithdrawal(
        sql,
        withdrawalId,
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
        "Erro interno ao processar o levantamento.",
      detail:
        getErrorMessage(error)
    });
  }
}
