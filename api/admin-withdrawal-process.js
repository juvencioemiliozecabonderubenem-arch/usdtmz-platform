import { neon } from "@neondatabase/serverless";
import { createHmac, timingSafeEqual } from "node:crypto";
import { TronWeb } from "tronweb";

const COOKIE = "usdtmz_admin_session";

const USDT_CONTRACT =
  "TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t";

const TRON_FULL_HOST = "https://api.trongrid.io";

const FEE_LIMIT = 100_000_000; // 100 TRX
const USDT_DECIMALS = 6;

const VALID_ORDER_STATUSES = [
  "PENDING",
  "PAYMENT_CONFIRMED",
  "USDT_SENT",
  "COMPLETED",
  "FAILED",
  "CANCELLED"
];

/* =========================================================
   BANCO
========================================================= */

function dbUrl() {
  return (
    process.env.URL_DO_BANCO_DE_DADOS ||
    process.env.POSTGRES_URL ||
    process.env.DATABASE_URL ||
    process.env.POSTGRES_URL_NON_POOLING ||
    process.env.DATABASE_URL_UNPOOLED
  );
}

/* =========================================================
   COMPARAÇÃO SEGURA
========================================================= */

function compare(a, b) {
  const A = Buffer.from(String(a));
  const B = Buffer.from(String(b));

  if (A.length !== B.length) return false;

  return timingSafeEqual(A, B);
}

/* =========================================================
   SESSÃO ADMIN
========================================================= */

function getAdminSession(req) {
  const raw = req.headers.cookie || "";

  const item = raw
    .split(";")
    .map(x => x.trim())
    .find(x => x.startsWith(`${COOKIE}=`));

  if (!item || !process.env.ADMIN_SESSION_SECRET) {
    return null;
  }

  const token = item
    .slice(COOKIE.length + 1)
    .split(".");

  if (token.length !== 2) {
    return null;
  }

  const [data, signature] = token;

  const expected = createHmac(
    "sha256",
    process.env.ADMIN_SESSION_SECRET
  )
    .update(data)
    .digest("base64url");

  if (!compare(signature, expected)) {
    return null;
  }

  try {
    const payload = JSON.parse(
      Buffer.from(data, "base64url").toString()
    );

    if (payload.id !== "admin") {
      return null;
    }

    if (Number(payload.exp) <= Date.now()) {
      return null;
    }

    return payload;
  } catch {
    return null;
  }
}

/* =========================================================
   TRON
========================================================= */

function getTron() {
  const privateKey =
    process.env.USDTMZ_TRON_PRIVATE_KEY;

  if (!privateKey) {
    throw new Error(
      "USDTMZ_TRON_PRIVATE_KEY não configurada."
    );
  }

  const tron = new TronWeb({
    fullHost: TRON_FULL_HOST,
    privateKey
  });

  const configuredAddress =
    process.env.USDTMZ_TRON_WALLET_ADDRESS;

  const derivedAddress =
    tron.address.fromPrivateKey(privateKey);

  const address =
    configuredAddress || derivedAddress;

  if (!tron.isAddress(address)) {
    throw new Error(
      "Carteira TRON da tesouraria inválida."
    );
  }

  /*
   * Segurança:
   * se uma carteira foi configurada explicitamente,
   * ela precisa corresponder à chave privada.
   */
  if (
    configuredAddress &&
    configuredAddress !== derivedAddress
  ) {
    throw new Error(
      "USDTMZ_TRON_WALLET_ADDRESS não corresponde à chave privada configurada."
    );
  }

  return {
    tron,
    address
  };
}

/* =========================================================
   VALIDAÇÃO USDT
========================================================= */

function usdtToSun(amount) {
  const value = Number(amount);

  if (!Number.isFinite(value) || value <= 0) {
    throw new Error("Quantidade USDT inválida.");
  }

  const sun = Math.round(
    value * 10 ** USDT_DECIMALS
  );

  if (!Number.isSafeInteger(sun) || sun <= 0) {
    throw new Error("Quantidade USDT inválida.");
  }

  return sun;
}

/* =========================================================
   SALDO TRX
========================================================= */

async function requireTrxBalance(tron, address) {
  const balanceSun =
    await tron.trx.getBalance(address);

  const trx =
    Number(balanceSun) / 1_000_000;

  if (!Number.isFinite(trx) || trx <= 0) {
    throw new Error(
      "Saldo TRX insuficiente para pagar a rede."
    );
  }

  return trx;
}

/* =========================================================
   SALDO USDT
========================================================= */

async function getUsdtBalance(tron, address) {
  const contract =
    await tron.contract().at(USDT_CONTRACT);

  const raw =
    await contract.balanceOf(address).call();

  const value = Number(raw);

  if (!Number.isFinite(value)) {
    throw new Error(
      "Não foi possível consultar o saldo USDT."
    );
  }

  return value / 10 ** USDT_DECIMALS;
}

/* =========================================================
   ENVIO USDT TRC20
========================================================= */

async function sendUSDT(to, amount) {
  const { tron, address } = getTron();

  if (!tron.isAddress(to)) {
    throw new Error(
      "Endereço TRON de destino inválido."
    );
  }

  const sun = usdtToSun(amount);

  await requireTrxBalance(tron, address);

  const usdtBalance =
    await getUsdtBalance(tron, address);

  const requestedUsdt =
    sun / 10 ** USDT_DECIMALS;

  if (usdtBalance < requestedUsdt) {
    throw new Error(
      `Saldo USDT insuficiente. Disponível: ${usdtBalance} USDT. Necessário: ${requestedUsdt} USDT.`
    );
  }

  const contract =
    await tron.contract().at(USDT_CONTRACT);

  /*
   * O retorno do send() é o TX hash.
   * Assim que este hash existir, a operação já pode
   * ser marcada como USDT_SENT para impedir novo envio.
   */
  const txHash =
    await contract.transfer(to, sun).send({
      feeLimit: FEE_LIMIT
    });

  if (!txHash) {
    throw new Error(
      "TRON não devolveu TX hash."
    );
  }

  return {
    txHash: String(txHash),
    amount: requestedUsdt,
    from: address,
    to
  };
}

/* =========================================================
   CONSULTAR TRANSAÇÃO SOLIDIFICADA
========================================================= */

async function getSolidifiedTransaction(txHash) {
  const response = await fetch(
    `${TRON_FULL_HOST}/walletsolidity/gettransactioninfobyid`,
    {
      method: "POST",
      headers: {
        "Content-Type": "application/json"
      },
      body: JSON.stringify({
        value: txHash
      })
    }
  );

  if (!response.ok) {
    throw new Error(
      `TRON retornou HTTP ${response.status}.`
    );
  }

  return await response.json();
}

/* =========================================================
   VERIFICAR EXECUÇÃO DA TRANSAÇÃO
========================================================= */

async function verifyTronTransaction(
  txHash,
  expectedTo,
  expectedAmount
) {
  const info =
    await getSolidifiedTransaction(txHash);

  /*
   * Se ainda não existe receipt solidificado,
   * não declaramos COMPLETED.
   */
  if (!info || Object.keys(info).length === 0) {
    return {
      confirmed: false,
      reason: "TRANSACTION_NOT_SOLIDIFIED"
    };
  }

  const receiptResult =
    info.receipt?.result ||
    info.receipt?.resMessage;

  if (
    receiptResult &&
    String(receiptResult).toUpperCase() !== "SUCCESS"
  ) {
    return {
      confirmed: false,
      failed: true,
      reason: String(receiptResult)
    };
  }

  /*
   * Algumas respostas TRON podem trazer contractResult.
   */
  if (
    info.receipt &&
    info.receipt.result &&
    String(info.receipt.result).toUpperCase() !== "SUCCESS"
  ) {
    return {
      confirmed: false,
      failed: true,
      reason: String(info.receipt.result)
    };
  }

  /*
   * Verificação adicional através dos logs do contrato USDT.
   *
   * Não marcamos COMPLETED simplesmente porque existe TX hash.
   * Primeiro exigimos que a execução esteja solidificada.
   */
  const logs = Array.isArray(info.log)
    ? info.log
    : [];

  if (logs.length === 0) {
    /*
     * Se não há logs, ainda não podemos provar que
     * houve o Transfer USDT esperado.
     */
    return {
      confirmed: false,
      reason: "USDT_TRANSFER_LOG_NOT_FOUND"
    };
  }

  const expectedAmountSun =
    usdtToSun(expectedAmount);

  const expectedToHex =
    TronWeb.address.toHex(expectedTo)
      .replace(/^41/, "")
      .toLowerCase();

  const transferTopic =
    "ddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef";

  for (const log of logs) {
    const address =
      String(log.address || "")
        .toLowerCase()
        .replace(/^0x/, "");

    const topics =
      Array.isArray(log.topics)
        ? log.topics.map(x =>
            String(x)
              .toLowerCase()
              .replace(/^0x/, "")
          )
        : [];

    if (
      address !==
      USDT_CONTRACT.slice(2).toLowerCase()
    ) {
      continue;
    }

    if (topics[0] !== transferTopic) {
      continue;
    }

    /*
     * Transfer(address indexed from,
     *          address indexed to,
     *          uint256 value)
     */

    const destinationTopic =
      topics[2] || "";

    const destinationMatches =
      destinationTopic.endsWith(
        expectedToHex
      );

    let amountMatches = false;

    try {
      const amountHex =
        String(topics[3] || "0");

      const transferAmount =
        BigInt(`0x${amountHex}`);

      amountMatches =
        transferAmount ===
        BigInt(expectedAmountSun);
    } catch {
      amountMatches = false;
    }

    if (
      destinationMatches &&
      amountMatches
    ) {
      return {
        confirmed: true,
        failed: false,
        reason: "USDT_TRANSFER_CONFIRMED"
      };
    }
  }

  return {
    confirmed: false,
    reason: "EXPECTED_USDT_TRANSFER_NOT_FOUND"
  };
}

/* =========================================================
   BLOQUEIO DA COMPRA
========================================================= */

async function lockPurchaseForSending(
  sql,
  orderId
) {
  const rows = await sql`
    UPDATE orders
    SET status = 'USDT_SENT',
        updated_at = NOW()
    WHERE order_id = ${orderId}
      AND operation = 'BUY_USDT_ADMIN'
      AND status = 'PAYMENT_CONFIRMED'
      AND blockchain_tx_hash IS NOT NULL
    RETURNING
      order_id,
      usdt_amount,
      status,
      blockchain_tx_hash
  `;

  return rows[0] || null;
}

/* =========================================================
   MARCAR TX COMO ENVIADA
========================================================= */

async function markOrderUsdtSent(
  sql,
  orderId,
  txHash
) {
  const rows = await sql`
    UPDATE orders
    SET status = 'USDT_SENT',
        blockchain_tx_hash = ${txHash},
        updated_at = NOW()
    WHERE order_id = ${orderId}
      AND operation = 'BUY_USDT_ADMIN'
      AND blockchain_tx_hash IS NULL
      AND status = 'PAYMENT_CONFIRMED'
    RETURNING
      order_id,
      status,
      blockchain_tx_hash
  `;

  return rows[0] || null;
}

/* =========================================================
   MARCAR COMPLETED
========================================================= */

async function markOrderCompleted(
  sql,
  orderId,
  txHash
) {
  const rows = await sql`
    UPDATE orders
    SET status = 'COMPLETED',
        blockchain_tx_hash = ${txHash},
        updated_at = NOW()
    WHERE order_id = ${orderId}
      AND operation = 'BUY_USDT_ADMIN'
      AND blockchain_tx_hash = ${txHash}
      AND status = 'USDT_SENT'
    RETURNING
      order_id,
      status,
      blockchain_tx_hash
  `;

  return rows[0] || null;
}

/* =========================================================
   MARCAR FAILED SOMENTE ANTES DO BROADCAST
========================================================= */

async function markOrderFailed(
  sql,
  orderId,
  message
) {
  await sql`
    UPDATE orders
    SET status = 'FAILED',
        updated_at = NOW()
    WHERE order_id = ${orderId}
      AND operation = 'BUY_USDT_ADMIN'
      AND blockchain_tx_hash IS NULL
      AND status = 'PAYMENT_CONFIRMED'
  `;

  console.error(
    "USDTMZ BINANCE TRANSFER FAILED:",
    orderId,
    message
  );
}

/* =========================================================
   API INTERNA
   CRIAR-COMPRA.JS USA ESTA FUNÇÃO
========================================================= */

export async function processAdminPurchaseToBinanceInternal(
  orderId
) {
  if (!orderId) {
    throw new Error(
      "orderId obrigatório."
    );
  }

  const databaseUrl = dbUrl();

  if (!databaseUrl) {
    throw new Error(
      "Banco de dados não configurado."
    );
  }

  const sql = neon(databaseUrl);

  /*
   * Buscar compra.
   */
  const rows = await sql`
    SELECT
      order_id,
      usdt_amount,
      status,
      blockchain_tx_hash
    FROM orders
    WHERE order_id = ${orderId}
      AND operation = 'BUY_USDT_ADMIN'
    LIMIT 1
  `;

  const order = rows[0];

  if (!order) {
    throw new Error(
      "Compra não encontrada."
    );
  }

  const status =
    String(order.status || "")
      .toUpperCase();

  /*
   * Se já existe TX hash, nunca fazemos outro envio.
   */
  if (order.blockchain_tx_hash) {
    const txHash =
      String(order.blockchain_tx_hash);

    /*
     * Se já estava USDT_SENT, tentamos apenas
     * confirmar a transação.
     */
    if (
      status === "USDT_SENT"
    ) {
      const verification =
        await verifyTronTransaction(
          txHash,
          process.env.BINANCE_USDT_TRON_ADDRESS,
          order.usdt_amount
        );

      if (verification.confirmed) {
        await markOrderCompleted(
          sql,
          orderId,
          txHash
        );

        return {
          success: true,
          status: "COMPLETED",
          tx_hash: txHash,
          already_sent: true
        };
      }

      return {
        success: true,
        status: "USDT_SENT",
        tx_hash: txHash,
        already_sent: true,
        message:
          "TX encontrada. Aguardar confirmação solidificada antes de marcar como COMPLETED."
      };
    }

    /*
     * Se já está COMPLETED, simplesmente devolve o resultado.
     */
    if (status === "COMPLETED") {
      return {
        success: true,
        status: "COMPLETED",
        tx_hash: txHash,
        already_sent: true
      };
    }

    /*
     * Segurança:
     * qualquer TX hash existente significa que não devemos
     * iniciar outro envio.
     */
    return {
      success: true,
      status,
      tx_hash: txHash,
      already_sent: true
    };
  }

  /*
   * Compra precisa estar confirmada pelo pagamento.
   */
  if (status !== "PAYMENT_CONFIRMED") {
    throw new Error(
      `Compra não está PAYMENT_CONFIRMED. Estado atual: ${order.status}`
    );
  }

  /*
   * Destino Binance exclusivamente do servidor.
   */
  const destination =
    process.env.BINANCE_USDT_TRON_ADDRESS;

  if (!destination) {
    throw new Error(
      "BINANCE_USDT_TRON_ADDRESS não configurado."
    );
  }

  const { tron } = getTron();

  if (!tron.isAddress(destination)) {
    throw new Error(
      "BINANCE_USDT_TRON_ADDRESS inválido."
    );
  }

  /*
   * Quantidade válida.
   */
  const amount =
    Number(order.usdt_amount);

  if (
    !Number.isFinite(amount) ||
    amount <= 0
  ) {
    throw new Error(
      "Quantidade USDT da compra inválida."
    );
  }

  try {
    /*
     * Antes de transmitir:
     * confirma que ainda há saldo suficiente.
     */
    const { address } = getTron();

    const usdtBalance =
      await getUsdtBalance(
        tron,
        address
      );

    if (usdtBalance < amount) {
      throw new Error(
        `Saldo USDT insuficiente. Disponível: ${usdtBalance} USDT. Necessário: ${amount} USDT.`
      );
    }

    /*
     * TRANSFERÊNCIA REAL.
     */
    const transfer =
      await sendUSDT(
        destination,
        amount
      );

    /*
     * MUITO IMPORTANTE:
     * o TX hash foi recebido.
     *
     * A partir deste ponto NÃO marcamos FAILED,
     * mesmo se uma verificação posterior falhar.
     */
    const saved =
      await markOrderUsdtSent(
        sql,
        orderId,
        transfer.txHash
      );

    /*
     * Se outro processo já gravou o TX,
     * nunca fazemos segundo envio.
     */
    if (!saved) {
      const current = await sql`
        SELECT
          status,
          blockchain_tx_hash
        FROM orders
        WHERE order_id = ${orderId}
        LIMIT 1
      `;

      if (
        current[0]?.blockchain_tx_hash
      ) {
        return {
          success: true,
          status:
            current[0].status,
          tx_hash:
            current[0].blockchain_tx_hash,
          already_sent: true
        };
      }

      throw new Error(
        "Não foi possível registrar o TX hash da transferência."
      );
    }

    /*
     * Agora verificamos se a blockchain já solidificou.
     */
    const verification =
      await verifyTronTransaction(
        transfer.txHash,
        destination,
        amount
      );

    if (verification.confirmed) {
      await markOrderCompleted(
        sql,
        orderId,
        transfer.txHash
      );

      return {
        success: true,
        status: "COMPLETED",
        tx_hash: transfer.txHash
      };
    }

    /*
     * TX existe, mas ainda não podemos afirmar COMPLETED.
     */
    return {
      success: true,
      status: "USDT_SENT",
      tx_hash: transfer.txHash,
      message:
        "USDT transmitido. Aguardar confirmação solidificada da TRON."
    };

  } catch (error) {
    console.error(
      "BINANCE TRANSFER ERROR:",
      error
    );

    /*
     * Se algum TX já foi gravado, NÃO marcamos FAILED.
     */
    const current = await sql`
      SELECT
        status,
        blockchain_tx_hash
      FROM orders
      WHERE order_id = ${orderId}
      LIMIT 1
    `;

    if (
      current[0]?.blockchain_tx_hash
    ) {
      return {
        success: true,
        status:
          current[0].status,
        tx_hash:
          current[0].blockchain_tx_hash,
        message:
          "TX já registrada. Não será feita nova transferência automaticamente."
      };
    }

    /*
     * Só podemos marcar FAILED quando sabemos
     * que nenhum TX hash foi registrado.
     */
    await markOrderFailed(
      sql,
      orderId,
      error?.message
    );

    throw error;
  }
}

/* =========================================================
   HANDLER ADMIN
========================================================= */

export default async function handler(
  req,
  res
) {
  const admin =
    getAdminSession(req);

  if (!admin) {
    return res.status(401).json({
      success: false,
      message:
        "Sessão administrativa inválida."
    });
  }

  if (req.method !== "POST") {
    return res.status(405).json({
      success: false,
      message:
        "Método não permitido."
    });
  }

  try {
    const {
      action,
      purchase_order_id,
      withdrawal_id
    } = req.body || {};

    /* =====================================================
       COMPRA ADMIN → BINANCE
    ===================================================== */

    if (
      action ===
        "admin_binance_transfer" &&
      purchase_order_id
    ) {
      const result =
        await processAdminPurchaseToBinanceInternal(
          purchase_order_id
        );

      return res.status(200).json(
        result
      );
    }

    /* =====================================================
       RETIRADA NORMAL
    ===================================================== */

    if (!withdrawal_id) {
      return res.status(400).json({
        success: false,
        message:
          "withdrawal_id obrigatório."
      });
    }

    const databaseUrl =
      dbUrl();

    if (!databaseUrl) {
      throw new Error(
        "Banco de dados não configurado."
      );
    }

    const sql =
      neon(databaseUrl);

    const rows = await sql`
      SELECT *
      FROM withdrawals
      WHERE id = ${withdrawal_id}
      LIMIT 1
    `;

    const withdrawal =
      rows[0];

    if (!withdrawal) {
      return res.status(404).json({
        success: false,
        message:
          "Levantamento não encontrado."
      });
    }

    /*
     * Somente AUTHORIZED pode ser processado.
     */
    if (
      String(withdrawal.status)
        .toUpperCase() !==
      "AUTHORIZED"
    ) {
      return res.status(400).json({
        success: false,
        message:
          `Estado inválido: ${withdrawal.status}`
      });
    }

    /*
     * Reserva o levantamento.
     */
    const locked =
      await sql`
        UPDATE withdrawals
        SET status = 'PROCESSING',
            updated_at = NOW()
        WHERE id = ${withdrawal_id}
          AND status = 'AUTHORIZED'
        RETURNING id
      `;

    if (!locked[0]) {
      return res.status(409).json({
        success: false,
        message:
          "Este levantamento já está sendo processado."
      });
    }

    try {
      const amount =
        withdrawal.amount_to_send ||
        withdrawal.amount;

      const tx =
        await sendUSDT(
          withdrawal.destination_address,
          amount
        );

      /*
       * TX hash recebido:
       * guardamos imediatamente.
       */
      await sql`
        UPDATE withdrawals
        SET status = 'PROCESSING',
            tx_hash = ${tx.txHash},
            updated_at = NOW()
        WHERE id = ${withdrawal_id}
          AND tx_hash IS NULL
      `;

      /*
       * Verificação solidificada.
       */
      const verification =
        await verifyTronTransaction(
          tx.txHash,
          withdrawal.destination_address,
          amount
        );

      if (verification.confirmed) {
        await sql`
          UPDATE withdrawals
          SET status = 'COMPLETED',
              tx_hash = ${tx.txHash},
              updated_at = NOW()
          WHERE id = ${withdrawal_id}
            AND tx_hash = ${tx.txHash}
        `;

        return res.status(200).json({
          success: true,
          status: "COMPLETED",
          tx_hash: tx.txHash
        });
      }

      /*
       * TX existe, mas ainda aguarda confirmação.
       * NÃO repetir.
       */
      return res.status(200).json({
        success: true,
        status: "PROCESSING",
        tx_hash: tx.txHash,
        message:
          "Transferência transmitida. Aguardar confirmação solidificada."
      });

    } catch (error) {
      console.error(
        "WITHDRAWAL ERROR:",
        error
      );

      /*
       * Se TX hash já foi gravado, nunca transformar
       * automaticamente em FAILED.
       */
      const current =
        await sql`
          SELECT
            status,
            tx_hash
          FROM withdrawals
          WHERE id = ${withdrawal_id}
          LIMIT 1
        `;

      if (
        current[0]?.tx_hash
      ) {
        return res.status(200).json({
          success: true,
          status:
            current[0].status,
          tx_hash:
            current[0].tx_hash,
          message:
            "TX já registrada. Não repetir automaticamente."
        });
      }

      /*
       * Sem TX hash:
       * pode ser marcado FAILED.
       */
      await sql`
        UPDATE withdrawals
        SET status = 'FAILED',
            updated_at = NOW()
        WHERE id = ${withdrawal_id}
          AND tx_hash IS NULL
      `;

      return res.status(500).json({
        success: false,
        status: "FAILED",
        message:
          error?.message ||
          "Erro ao processar transferência."
      });
    }

  } catch (error) {
    console.error(
      "ADMIN WITHDRAWAL PROCESS ERROR:",
      error
    );

    return res.status(500).json({
      success: false,
      message:
        error?.message ||
        "Erro ao processar transferência."
    });
  }
}
