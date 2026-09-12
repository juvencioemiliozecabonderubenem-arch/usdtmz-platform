import { neon } from "@neondatabase/serverless";
import { createHmac, timingSafeEqual } from "node:crypto";
import { TronWeb } from "tronweb";

const COOKIE = "usdtmz_admin_session";

const HOST =
  process.env.TRON_HOST ||
  "https://api.trongrid.io";

const CONTRACT =
  process.env.USDT_TRON_CONTRACT ||
  "TR7NHqjeKQXGTCi8q8ZY4pL8otSzgjLj6t";

const FEE_LIMIT = 100_000_000;
const DECIMALS = 6;

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

function safeEqual(a, b) {
  const A = Buffer.from(String(a));
  const B = Buffer.from(String(b));

  return (
    A.length === B.length &&
    timingSafeEqual(A, B)
  );
}

/* =========================================================
   SESSÃO ADMIN
========================================================= */

function adminSession(req) {
  const cookie = (req.headers.cookie || "")
    .split(";")
    .map(x => x.trim())
    .find(x =>
      x.startsWith(`${COOKIE}=`)
    );

  if (
    !cookie ||
    !process.env.ADMIN_SESSION_SECRET
  ) {
    return null;
  }

  const parts = cookie
    .slice(COOKIE.length + 1)
    .split(".");

  if (parts.length !== 2) {
    return null;
  }

  const [data, signature] = parts;

  const expected = createHmac(
    "sha256",
    process.env.ADMIN_SESSION_SECRET
  )
    .update(data)
    .digest("base64url");

  if (!safeEqual(signature, expected)) {
    return null;
  }

  try {
    const payload = JSON.parse(
      Buffer.from(
        data,
        "base64url"
      ).toString()
    );

    if (
      payload.id !== "admin" ||
      Number(payload.exp) <= Date.now()
    ) {
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
  const key =
    process.env.USDTMZ_TRON_PRIVATE_KEY;

  if (!key) {
    throw new Error(
      "USDTMZ_TRON_PRIVATE_KEY não configurada."
    );
  }

  const tron = new TronWeb({
    fullHost: HOST,
    privateKey: key
  });

  const derived =
    tron.address.fromPrivateKey(key);

  if (!derived) {
    throw new Error(
      "Não foi possível derivar a carteira TRON da chave privada."
    );
  }

  const configured =
    process.env.USDTMZ_TRON_WALLET_ADDRESS;

  const address =
    configured || derived;

  if (!tron.isAddress(address)) {
    throw new Error(
      "Carteira TRON inválida."
    );
  }

  if (
    configured &&
    configured !== derived
  ) {
    throw new Error(
      "A carteira configurada não corresponde à chave privada."
    );
  }

  return {
    tron,
    address
  };
}

/* =========================================================
   CONVERSÃO USDT → UNIDADES
========================================================= */

function amountSun(amount) {
  const n = Number(amount);

  if (
    !Number.isFinite(n) ||
    n <= 0
  ) {
    throw new Error(
      "Quantidade USDT inválida."
    );
  }

  const sun = Math.round(
    n * 10 ** DECIMALS
  );

  if (
    !Number.isSafeInteger(sun) ||
    sun <= 0
  ) {
    throw new Error(
      "Quantidade USDT inválida."
    );
  }

  return sun;
}

/* =========================================================
   SALDO USDT REAL
========================================================= */

async function usdtBalance(
  tron,
  address
) {
  const contract =
    await tron.contract().at(CONTRACT);

  const raw =
    Number(
      await contract
        .balanceOf(address)
        .call()
    );

  if (!Number.isFinite(raw)) {
    throw new Error(
      "Não foi possível consultar o saldo USDT."
    );
  }

  return (
    raw / 10 ** DECIMALS
  );
}

/* =========================================================
   ENVIO REAL DE USDT TRC20
========================================================= */

async function sendUSDT(
  destination,
  amount
) {
  const {
    tron,
    address
  } = getTron();

  if (
    !tron.isAddress(destination)
  ) {
    throw new Error(
      "Endereço TRON de destino inválido."
    );
  }

  if (
    !tron.isAddress(CONTRACT)
  ) {
    throw new Error(
      "Contrato USDT TRON inválido."
    );
  }

  const sun =
    amountSun(amount);

  const trx =
    Number(
      await tron.trx.getBalance(address)
    ) / 1_000_000;

  if (
    !Number.isFinite(trx) ||
    trx <= 0
  ) {
    throw new Error(
      "Saldo TRX insuficiente para pagar a rede."
    );
  }

  const balance =
    await usdtBalance(
      tron,
      address
    );

  const value =
    sun / 10 ** DECIMALS;

  if (
    balance < value
  ) {
    throw new Error(
      `Saldo USDT insuficiente. Disponível: ${balance} USDT. Necessário: ${value} USDT.`
    );
  }

  const contract =
    await tron.contract().at(
      CONTRACT
    );

  /*
   * A partir daqui existe possibilidade real
   * de transmissão para a blockchain.
   *
   * O chamador NÃO deve assumir que um erro posterior
   * significa que a transferência não aconteceu.
   */
  const txHash =
    await contract
      .transfer(
        destination,
        sun
      )
      .send({
        feeLimit: FEE_LIMIT
      });

  if (!txHash) {
    throw new Error(
      "TRON não devolveu TX hash."
    );
  }

  return {
    txHash: String(txHash),
    amount: value,
    from: address,
    to: destination
  };
}

/* =========================================================
   HEX DO CONTRATO TRON
========================================================= */

function contractHex() {
  const hex =
    TronWeb.address
      .toHex(CONTRACT)
      .replace(/^41/, "")
      .replace(/^0x/, "")
      .toLowerCase();

  return hex;
}

/* =========================================================
   HEX DO ENDEREÇO TRON
========================================================= */

function addressHex(address) {
  return TronWeb.address
    .toHex(address)
    .replace(/^41/, "")
    .replace(/^0x/, "")
    .toLowerCase();
}

/* =========================================================
   VERIFICAÇÃO REAL DA TRANSAÇÃO
========================================================= */

async function verifyTransaction(
  txHash,
  source,
  destination,
  amount
) {
  if (!txHash) {
    return {
      confirmed: false,
      reason: "TX_HASH_MISSING"
    };
  }

  if (
    !TronWeb.isAddress(source)
  ) {
    throw new Error(
      "Endereço TRON de origem inválido."
    );
  }

  if (
    !TronWeb.isAddress(destination)
  ) {
    throw new Error(
      "Endereço TRON de destino inválido."
    );
  }

  const response =
    await fetch(
      `${HOST}/walletsolidity/gettransactioninfobyid`,
      {
        method: "POST",
        headers: {
          "Content-Type":
            "application/json"
        },
        body: JSON.stringify({
          value: txHash
        })
      }
    );

  if (!response.ok) {
    throw new Error(
      `TRON HTTP ${response.status}.`
    );
  }

  const info =
    await response.json();

  if (
    !info ||
    Object.keys(info).length === 0
  ) {
    return {
      confirmed: false,
      reason: "NOT_SOLIDIFIED"
    };
  }

  /*
   * Resultado da execução da transação.
   */
  if (
    info.receipt?.result &&
    String(
      info.receipt.result
    ).toUpperCase() !==
      "SUCCESS"
  ) {
    return {
      confirmed: false,
      failed: true,
      reason: String(
        info.receipt.result
      )
    };
  }

  const logs =
    Array.isArray(info.log)
      ? info.log
      : [];

  /*
   * keccak256("Transfer(address,address,uint256)")
   */
  const transferTopic =
    "ddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef";

  const expectedContract =
    contractHex();

  const expectedFrom =
    addressHex(source);

  const expectedTo =
    addressHex(destination);

  const expectedAmount =
    BigInt(
      amountSun(amount)
    );

  for (
    const log of logs
  ) {
    const logAddress =
      String(
        log.address || ""
      )
        .replace(/^0x/, "")
        .replace(/^41/, "")
        .toLowerCase();

    const topics =
      Array.isArray(log.topics)
        ? log.topics.map(
            x =>
              String(x)
                .replace(/^0x/, "")
                .toLowerCase()
          )
        : [];

    /*
     * Confirma que o evento veio
     * exatamente do contrato USDT.
     */
    if (
      logAddress !==
      expectedContract
    ) {
      continue;
    }

    if (
      topics[0] !==
      transferTopic
    ) {
      continue;
    }

    /*
     * ERC20/TRC20 Transfer:
     *
     * topics[1] = from
     * topics[2] = to
     * data      = amount
     */

    const fromMatches =
      (topics[1] || "")
        .endsWith(
          expectedFrom
        );

    const toMatches =
      (topics[2] || "")
        .endsWith(
          expectedTo
        );

    if (
      !fromMatches ||
      !toMatches
    ) {
      continue;
    }

    try {
      /*
       * Em logs TRON, a quantidade
       * pode aparecer no data ou topics[3],
       * dependendo da representação.
       */
      let transferred;

      if (
        topics[3]
      ) {
        transferred =
          BigInt(
            `0x${topics[3]}`
          );
      } else if (
        log.data
      ) {
        const data =
          String(
            log.data
          )
            .replace(
              /^0x/,
              ""
            );

        transferred =
          BigInt(
            `0x${data}`
          );
      } else {
        continue;
      }

      if (
        transferred ===
        expectedAmount
      ) {
        return {
          confirmed: true,
          reason:
            "USDT_TRANSFER_CONFIRMED",
          from: source,
          to: destination,
          amount:
            amount
        };
      }
    } catch {
      continue;
    }
  }

  return {
    confirmed: false,
    reason:
      "TRANSFER_NOT_CONFIRMED"
  };
}

/* =========================================================
   COMPRA ADMIN → BINANCE
========================================================= */

export async function
processAdminPurchaseToBinanceInternal(
  orderId
) {
  if (!orderId) {
    throw new Error(
      "orderId obrigatório."
    );
  }

  const url =
    dbUrl();

  if (!url) {
    throw new Error(
      "Banco de dados não configurado."
    );
  }

  const sql =
    neon(url);

  /*
   * A carteira que realmente envia
   * o USDT.
   */
  const {
    address: treasuryAddress
  } = getTron();

  const rows =
    await sql`
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

  const order =
    rows[0];

  if (!order) {
    throw new Error(
      "Compra não encontrada."
    );
  }

  let status =
    String(
      order.status || ""
    ).toUpperCase();

  const destination =
    process.env
      .BINANCE_USDT_TRON_ADDRESS;

  if (!destination) {
    throw new Error(
      "BINANCE_USDT_TRON_ADDRESS não configurado."
    );
  }

  if (
    !TronWeb.isAddress(
      destination
    )
  ) {
    throw new Error(
      "Endereço Binance TRON inválido."
    );
  }

  /*
   * -------------------------------------------------------
   * JÁ EXISTE TX
   * -------------------------------------------------------
   *
   * Nunca envia novamente automaticamente.
   */
  if (
    order.blockchain_tx_hash
  ) {
    const check =
      await verifyTransaction(
        order.blockchain_tx_hash,
        treasuryAddress,
        destination,
        order.usdt_amount
      );

    if (
      check.confirmed &&
      status === "USDT_SENT"
    ) {
      await sql`
        UPDATE orders
        SET status = 'COMPLETED',
            updated_at = NOW()
        WHERE order_id = ${orderId}
          AND status = 'USDT_SENT'
          AND blockchain_tx_hash =
              ${order.blockchain_tx_hash}
      `;

      return {
        success: true,
        status: "COMPLETED",
        tx_hash:
          order.blockchain_tx_hash,
        already_sent: true
      };
    }

    return {
      success: true,
      status,
      tx_hash:
        order.blockchain_tx_hash,
      already_sent: true,
      message:
        check.confirmed
          ? "Transferência já confirmada."
          : "TX registrada. Aguardando confirmação da TRON."
    };
  }

  /*
   * -------------------------------------------------------
   * PROCESSAMENTO EM ANDAMENTO
   * -------------------------------------------------------
   *
   * Se outro processo já entrou aqui, NÃO tentar enviar.
   */
  if (
    status === "PROCESSING"
  ) {
    return {
      success: true,
      status: "PROCESSING",
      message:
        "Esta compra já está em processamento. Não será feito novo envio automaticamente."
    };
  }

  /*
   * -------------------------------------------------------
   * PAGAMENTO CONFIRMADO
   * -------------------------------------------------------
   */

  if (
    status !==
    "PAYMENT_CONFIRMED"
  ) {
    throw new Error(
      `Compra não está PAYMENT_CONFIRMED. Estado atual: ${order.status}`
    );
  }

  const amount =
    Number(
      order.usdt_amount
    );

  if (
    !Number.isFinite(amount) ||
    amount <= 0
  ) {
    throw new Error(
      "Quantidade USDT inválida."
    );
  }

  /*
   * -------------------------------------------------------
   * LOCK ATÔMICO
   * -------------------------------------------------------
   *
   * MUITO IMPORTANTE:
   *
   * Primeiro mudamos:
   *
   * PAYMENT_CONFIRMED
   *        ↓
   * PROCESSING
   *
   * Só um processo consegue fazer isso.
   *
   * Isso acontece ANTES de enviar USDT.
   *
   * Assim evitamos:
   *
   * processo A → sendUSDT()
   * processo B → sendUSDT()
   *
   * ao mesmo tempo.
   */
  const locked =
    await sql`
      UPDATE orders
      SET status = 'PROCESSING',
          updated_at = NOW()
      WHERE order_id = ${orderId}
        AND operation = 'BUY_USDT_ADMIN'
        AND status = 'PAYMENT_CONFIRMED'
        AND blockchain_tx_hash IS NULL
      RETURNING order_id
    `;

  if (!locked[0]) {
    const current =
      await sql`
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

    return {
      success: true,
      status:
        current[0]?.status ||
        "PROCESSING",
      message:
        "A compra já está sendo processada. Não será feito novo envio."
    };
  }

  /*
   * -------------------------------------------------------
   * VERIFICA SALDO REAL ANTES DO ENVIO
   * -------------------------------------------------------
   */

  try {
    const {
      tron
    } = getTron();

    const balance =
      await usdtBalance(
        tron,
        treasuryAddress
      );

    if (
      balance < amount
    ) {
      await sql`
        UPDATE orders
        SET status = 'PAYMENT_CONFIRMED',
            updated_at = NOW()
        WHERE order_id = ${orderId}
          AND status = 'PROCESSING'
          AND blockchain_tx_hash IS NULL
      `;

      throw new Error(
        `USDT insuficiente para executar a compra. Disponível: ${balance} USDT. Necessário: ${amount} USDT.`
      );
    }

    /*
     * -----------------------------------------------------
     * ENVIO REAL
     * -----------------------------------------------------
     */

    const tx =
      await sendUSDT(
        destination,
        amount
      );

    /*
     * -----------------------------------------------------
     * REGISTRA TX IMEDIATAMENTE
     * -----------------------------------------------------
     */

    const saved =
      await sql`
        UPDATE orders
        SET status = 'USDT_SENT',
            blockchain_tx_hash =
              ${tx.txHash},
            updated_at = NOW()
        WHERE order_id = ${orderId}
          AND status = 'PROCESSING'
          AND blockchain_tx_hash IS NULL
        RETURNING order_id
      `;

    /*
     * Se por algum motivo outro processo
     * já registrou uma TX, NÃO tentamos outra.
     */
    if (!saved[0]) {
      const current =
        await sql`
          SELECT
            status,
            blockchain_tx_hash
          FROM orders
          WHERE order_id = ${orderId}
          LIMIT 1
        `;

      return {
        success: true,
        status:
          current[0]?.status ||
          "USDT_SENT",
        tx_hash:
          current[0]?.blockchain_tx_hash ||
          tx.txHash,
        already_sent: true
      };
    }

    /*
     * -----------------------------------------------------
     * CONFIRMAÇÃO BLOCKCHAIN
     * -----------------------------------------------------
     */

    const check =
      await verifyTransaction(
        tx.txHash,
        treasuryAddress,
        destination,
        amount
      );

    if (
      check.confirmed
    ) {
      await sql`
        UPDATE orders
        SET status = 'COMPLETED',
            updated_at = NOW()
        WHERE order_id = ${orderId}
          AND status = 'USDT_SENT'
          AND blockchain_tx_hash =
              ${tx.txHash}
      `;

      return {
        success: true,
        status: "COMPLETED",
        tx_hash:
          tx.txHash,
        amount: amount
      };
    }

    /*
     * TX já foi registrada.
     *
     * Nunca marcar FAILED simplesmente
     * porque a confirmação ainda não apareceu.
     */
    return {
      success: true,
      status: "USDT_SENT",
      tx_hash:
        tx.txHash,
      amount: amount,
      message:
        "TX enviada e registrada. Aguardar confirmação da TRON."
    };

  } catch (error) {
    console.error(
      "ADMIN PURCHASE TRANSFER ERROR:",
      error
    );

    /*
     * -----------------------------------------------------
     * PROTEÇÃO CONTRA TX PERDIDA
     * -----------------------------------------------------
     *
     * Se o sendUSDT() falhar depois de a rede
     * eventualmente ter recebido a operação,
     * NÃO podemos assumir que não houve envio.
     *
     * Por isso:
     *
     * NÃO voltamos automaticamente para FAILED.
     * NÃO fazemos novo envio.
     *
     * O pedido permanece PROCESSING para investigação/
     * confirmação posterior.
     */
    const current =
      await sql`
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
          "TX registrada. Não será feito novo envio."
      };
    }

    /*
     * Se não existe TX hash, mantemos PROCESSING.
     *
     * Isso é deliberado:
     * um erro de rede não prova que a transferência
     * não aconteceu.
     */
    await sql`
      UPDATE orders
      SET status = 'PROCESSING',
          updated_at = NOW()
      WHERE order_id = ${orderId}
        AND blockchain_tx_hash IS NULL
    `;

    throw new Error(
      "Não foi possível determinar com segurança o resultado da transferência. A operação foi mantida em PROCESSING para evitar duplicação."
    );
  }
}

/* =========================================================
   HANDLER
========================================================= */

export default async function handler(
  req,
  res
) {
  if (
    !adminSession(req)
  ) {
    return res.status(401).json({
      success: false,
      message:
        "Sessão administrativa inválida."
    });
  }

  if (
    req.method !== "POST"
  ) {
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
       MÉTODO 1
       COMPRA ADMIN → BINANCE
    ===================================================== */

    if (
      action ===
        "admin_binance_transfer" &&
      purchase_order_id
    ) {
      return res.status(200).json(
        await processAdminPurchaseToBinanceInternal(
          purchase_order_id
        )
      );
    }

    /* =====================================================
       MÉTODO 2
       RETIRADA NORMAL
    ===================================================== */

    if (!withdrawal_id) {
      return res.status(400).json({
        success: false,
        message:
          "withdrawal_id obrigatório."
      });
    }

    const url =
      dbUrl();

    if (!url) {
      throw new Error(
        "Banco de dados não configurado."
      );
    }

    const sql =
      neon(url);

    const rows =
      await sql`
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

    const withdrawalStatus =
      String(
        withdrawal.status || ""
      ).toUpperCase();

    /*
     * Somente retirada autorizada pode
     * entrar no processamento.
     */
    if (
      withdrawalStatus !==
      "AUTHORIZED"
    ) {
      return res.status(400).json({
        success: false,
        message:
          `Estado inválido: ${withdrawal.status}`
      });
    }

    /*
     * -----------------------------------------------------
     * LOCK ATÔMICO
     * -----------------------------------------------------
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

    const amount =
      Number(
        withdrawal.amount_to_send ||
        withdrawal.amount
      );

    if (
      !Number.isFinite(amount) ||
      amount <= 0
    ) {
      await sql`
        UPDATE withdrawals
        SET status = 'FAILED',
            updated_at = NOW()
        WHERE id = ${withdrawal_id}
          AND status = 'PROCESSING'
          AND tx_hash IS NULL
      `;

      return res.status(400).json({
        success: false,
        status: "FAILED",
        message:
          "Quantidade USDT inválida."
      });
    }

    if (
      !withdrawal.destination_address ||
      !TronWeb.isAddress(
        withdrawal.destination_address
      )
    ) {
      await sql`
        UPDATE withdrawals
        SET status = 'FAILED',
            updated_at = NOW()
        WHERE id = ${withdrawal_id}
          AND status = 'PROCESSING'
          AND tx_hash IS NULL
      `;

      return res.status(400).json({
        success: false,
        status: "FAILED",
        message:
          "Endereço TRON de destino inválido."
      });
    }

    try {
      const {
        address:
          treasuryAddress
      } = getTron();

      /*
       * ---------------------------------------------------
       * SALDO REAL
       * ---------------------------------------------------
       */

      const {
        tron
      } = getTron();

      const balance =
        await usdtBalance(
          tron,
          treasuryAddress
        );

      if (
        balance < amount
      ) {
        await sql`
          UPDATE withdrawals
          SET status = 'FAILED',
              updated_at = NOW()
          WHERE id = ${withdrawal_id}
            AND status = 'PROCESSING'
            AND tx_hash IS NULL
        `;

        return res.status(400).json({
          success: false,
          status: "FAILED",
          message:
            `Saldo USDT insuficiente. Disponível: ${balance} USDT. Necessário: ${amount} USDT.`
        });
      }

      /*
       * ---------------------------------------------------
       * ENVIO REAL
       * ---------------------------------------------------
       */

      const tx =
        await sendUSDT(
          withdrawal.destination_address,
          amount
        );

      /*
       * ---------------------------------------------------
       * REGISTRA TX IMEDIATAMENTE
       * ---------------------------------------------------
       */

      const saved =
        await sql`
          UPDATE withdrawals
          SET tx_hash = ${tx.txHash},
              status = 'PROCESSING',
              updated_at = NOW()
          WHERE id = ${withdrawal_id}
            AND status = 'PROCESSING'
            AND tx_hash IS NULL
          RETURNING id
        `;

      if (!saved[0]) {
        const current =
          await sql`
            SELECT
              status,
              tx_hash
            FROM withdrawals
            WHERE id = ${withdrawal_id}
            LIMIT 1
          `;

        return res.status(200).json({
          success: true,
          status:
            current[0]?.status ||
            "PROCESSING",
          tx_hash:
            current[0]?.tx_hash ||
            tx.txHash,
          already_sent: true
        });
      }

      /*
       * ---------------------------------------------------
       * CONFIRMA BLOCKCHAIN
       * ---------------------------------------------------
       */

      const check =
        await verifyTransaction(
          tx.txHash,
          treasuryAddress,
          withdrawal.destination_address,
          amount
        );

      if (
        check.confirmed
      ) {
        await sql`
          UPDATE withdrawals
          SET status = 'COMPLETED',
              updated_at = NOW()
          WHERE id = ${withdrawal_id}
            AND status = 'PROCESSING'
            AND tx_hash = ${tx.txHash}
        `;

        return res.status(200).json({
          success: true,
          status: "COMPLETED",
          tx_hash:
            tx.txHash,
          amount: amount
        });
      }

      return res.status(200).json({
        success: true,
        status: "PROCESSING",
        tx_hash:
          tx.txHash,
        amount: amount,
        message:
          "TX enviada e registrada. Aguardar confirmação da TRON."
      });

    } catch (error) {
      console.error(
        "ADMIN WITHDRAWAL TRANSFER ERROR:",
        error
      );

      /*
       * Se TX já existe, nunca reenviar.
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
            "TX já registrada. Não repetir."
        });
      }

      /*
       * Sem TX registrada, ainda assim NÃO marcamos
       * FAILED automaticamente depois de uma possível
       * falha de rede.
       *
       * Mantemos PROCESSING para investigação segura.
       */
      await sql`
        UPDATE withdrawals
        SET status = 'PROCESSING',
            updated_at = NOW()
        WHERE id = ${withdrawal_id}
          AND tx_hash IS NULL
      `;

      return res.status(500).json({
        success: false,
        status: "PROCESSING",
        message:
          "Não foi possível determinar com segurança o resultado da transferência. A operação foi mantida em PROCESSING para evitar duplicação."
      });
    }

  } catch (error) {
    console.error(
      "ADMIN WITHDRAWAL PROCESS:",
      error
    );

    return res.status(500).json({
      success: false,
      message:
        error.message ||
        "Erro interno."
    });
  }
}
