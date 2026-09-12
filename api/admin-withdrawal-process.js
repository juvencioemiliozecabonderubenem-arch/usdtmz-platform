import { neon } from "@neondatabase/serverless";
import { createHmac, timingSafeEqual } from "node:crypto";
import { TronWeb } from "tronweb";

const COOKIE = "usdtmz_admin_session";
const HOST = "https://api.trongrid.io";
const CONTRACT = "TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t";
const FEE_LIMIT = 100_000_000;
const DECIMALS = 6;

function dbUrl() {
  return process.env.URL_DO_BANCO_DE_DADOS ||
    process.env.POSTGRES_URL ||
    process.env.DATABASE_URL ||
    process.env.POSTGRES_URL_NON_POOLING ||
    process.env.DATABASE_URL_UNPOOLED;
}

function safeEqual(a, b) {
  const A = Buffer.from(String(a));
  const B = Buffer.from(String(b));
  return A.length === B.length && timingSafeEqual(A, B);
}

function adminSession(req) {
  const cookie = (req.headers.cookie || "")
    .split(";")
    .map(x => x.trim())
    .find(x => x.startsWith(`${COOKIE}=`));

  if (!cookie || !process.env.ADMIN_SESSION_SECRET) return null;

  const parts = cookie.slice(COOKIE.length + 1).split(".");
  if (parts.length !== 2) return null;

  const [data, signature] = parts;

  const expected = createHmac(
    "sha256",
    process.env.ADMIN_SESSION_SECRET
  ).update(data).digest("base64url");

  if (!safeEqual(signature, expected)) return null;

  try {
    const payload = JSON.parse(
      Buffer.from(data, "base64url").toString()
    );

    if (payload.id !== "admin" || Number(payload.exp) <= Date.now()) {
      return null;
    }

    return payload;
  } catch {
    return null;
  }
}

function getTron() {
  const key = process.env.USDTMZ_TRON_PRIVATE_KEY;
  if (!key) throw new Error("USDTMZ_TRON_PRIVATE_KEY não configurada.");

  const tron = new TronWeb({
    fullHost: HOST,
    privateKey: key
  });

  const derived = tron.address.fromPrivateKey(key);
  const configured = process.env.USDTMZ_TRON_WALLET_ADDRESS;
  const address = configured || derived;

  if (!tron.isAddress(address)) {
    throw new Error("Carteira TRON inválida.");
  }

  if (configured && configured !== derived) {
    throw new Error(
      "A carteira configurada não corresponde à chave privada."
    );
  }

  return { tron, address };
}

function amountSun(amount) {
  const n = Number(amount);

  if (!Number.isFinite(n) || n <= 0) {
    throw new Error("Quantidade USDT inválida.");
  }

  const sun = Math.round(n * 10 ** DECIMALS);

  if (!Number.isSafeInteger(sun) || sun <= 0) {
    throw new Error("Quantidade USDT inválida.");
  }

  return sun;
}

async function usdtBalance(tron, address) {
  const contract = await tron.contract().at(CONTRACT);
  const raw = Number(await contract.balanceOf(address).call());

  if (!Number.isFinite(raw)) {
    throw new Error("Não foi possível consultar o saldo USDT.");
  }

  return raw / 10 ** DECIMALS;
}

async function sendUSDT(destination, amount) {
  const { tron, address } = getTron();

  if (!tron.isAddress(destination)) {
    throw new Error("Endereço TRON de destino inválido.");
  }

  const sun = amountSun(amount);
  const trx = Number(await tron.trx.getBalance(address)) / 1_000_000;

  if (!Number.isFinite(trx) || trx <= 0) {
    throw new Error("Saldo TRX insuficiente para pagar a rede.");
  }

  const balance = await usdtBalance(tron, address);
  const value = sun / 10 ** DECIMALS;

  if (balance < value) {
    throw new Error(
      `Saldo USDT insuficiente. Disponível: ${balance} USDT. Necessário: ${value} USDT.`
    );
  }

  const contract = await tron.contract().at(CONTRACT);

  const txHash = await contract.transfer(destination, sun).send({
    feeLimit: FEE_LIMIT
  });

  if (!txHash) throw new Error("TRON não devolveu TX hash.");

  return {
    txHash: String(txHash),
    amount: value,
    from: address,
    to: destination
  };
}

async function verifyTransaction(txHash, destination, amount) {
  const response = await fetch(
    `${HOST}/walletsolidity/gettransactioninfobyid`,
    {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ value: txHash })
    }
  );

  if (!response.ok) {
    throw new Error(`TRON HTTP ${response.status}.`);
  }

  const info = await response.json();

  if (!info || Object.keys(info).length === 0) {
    return { confirmed: false, reason: "NOT_SOLIDIFIED" };
  }

  if (
    info.receipt?.result &&
    String(info.receipt.result).toUpperCase() !== "SUCCESS"
  ) {
    return {
      confirmed: false,
      failed: true,
      reason: String(info.receipt.result)
    };
  }

  const logs = Array.isArray(info.log) ? info.log : [];
  const transferTopic =
    "ddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef";

  const expectedTo = TronWeb.address
    .toHex(destination)
    .replace(/^41/, "")
    .toLowerCase();

  const expectedAmount = BigInt(amountSun(amount));

  for (const log of logs) {
    const address = String(log.address || "")
      .replace(/^0x/, "")
      .toLowerCase();

    const topics = Array.isArray(log.topics)
      ? log.topics.map(x =>
          String(x).replace(/^0x/, "").toLowerCase()
        )
      : [];

    if (address !== CONTRACT.slice(2).toLowerCase()) continue;
    if (topics[0] !== transferTopic) continue;

    const toMatches = (topics[2] || "").endsWith(expectedTo);

    try {
      const transferred = BigInt(`0x${topics[3] || "0"}`);

      if (toMatches && transferred === expectedAmount) {
        return {
          confirmed: true,
          reason: "USDT_TRANSFER_CONFIRMED"
        };
      }
    } catch {}
  }

  return {
    confirmed: false,
    reason: "TRANSFER_NOT_CONFIRMED"
  };
}

/* =========================================================
   COMPRA ADMIN → BINANCE
========================================================= */

export async function processAdminPurchaseToBinanceInternal(orderId) {
  if (!orderId) throw new Error("orderId obrigatório.");

  const url = dbUrl();
  if (!url) throw new Error("Banco de dados não configurado.");

  const sql = neon(url);

  const rows = await sql`
    SELECT order_id, usdt_amount, status, blockchain_tx_hash
    FROM orders
    WHERE order_id = ${orderId}
      AND operation = 'BUY_USDT_ADMIN'
    LIMIT 1
  `;

  const order = rows[0];
  if (!order) throw new Error("Compra não encontrada.");

  const status = String(order.status || "").toUpperCase();
  const destination = process.env.BINANCE_USDT_TRON_ADDRESS;

  if (!destination) {
    throw new Error("BINANCE_USDT_TRON_ADDRESS não configurado.");
  }

  if (!TronWeb.isAddress(destination)) {
    throw new Error("Endereço Binance TRON inválido.");
  }

  /* Nunca enviar novamente se já existe TX. */
  if (order.blockchain_tx_hash) {
    if (status === "USDT_SENT") {
      const check = await verifyTransaction(
        order.blockchain_tx_hash,
        destination,
        order.usdt_amount
      );

      if (check.confirmed) {
        await sql`
          UPDATE orders
          SET status = 'COMPLETED', updated_at = NOW()
          WHERE order_id = ${orderId}
            AND status = 'USDT_SENT'
            AND blockchain_tx_hash = ${order.blockchain_tx_hash}
        `;

        return {
          success: true,
          status: "COMPLETED",
          tx_hash: order.blockchain_tx_hash,
          already_sent: true
        };
      }
    }

    return {
      success: true,
      status,
      tx_hash: order.blockchain_tx_hash,
      already_sent: true
    };
  }

  if (status !== "PAYMENT_CONFIRMED") {
    throw new Error(
      `Compra não está PAYMENT_CONFIRMED. Estado atual: ${order.status}`
    );
  }

  const amount = Number(order.usdt_amount);

  if (!Number.isFinite(amount) || amount <= 0) {
    throw new Error("Quantidade USDT inválida.");
  }

  try {
    const tx = await sendUSDT(destination, amount);

    /* TX registrada imediatamente: proteção contra duplicação. */
    const saved = await sql`
      UPDATE orders
      SET status = 'USDT_SENT',
          blockchain_tx_hash = ${tx.txHash},
          updated_at = NOW()
      WHERE order_id = ${orderId}
        AND status = 'PAYMENT_CONFIRMED'
        AND blockchain_tx_hash IS NULL
      RETURNING order_id
    `;

    if (!saved[0]) {
      return {
        success: true,
        status: "USDT_SENT",
        tx_hash: tx.txHash,
        already_sent: true
      };
    }

    const check = await verifyTransaction(
      tx.txHash,
      destination,
      amount
    );

    if (check.confirmed) {
      await sql`
        UPDATE orders
        SET status = 'COMPLETED', updated_at = NOW()
        WHERE order_id = ${orderId}
          AND status = 'USDT_SENT'
          AND blockchain_tx_hash = ${tx.txHash}
      `;

      return {
        success: true,
        status: "COMPLETED",
        tx_hash: tx.txHash
      };
    }

    return {
      success: true,
      status: "USDT_SENT",
      tx_hash: tx.txHash,
      message: "TX enviada. Aguardar confirmação da TRON."
    };

  } catch (error) {
    const current = await sql`
      SELECT status, blockchain_tx_hash
      FROM orders
      WHERE order_id = ${orderId}
      LIMIT 1
    `;

    /* Se existe TX, nunca marcar FAILED nem reenviar. */
    if (current[0]?.blockchain_tx_hash) {
      return {
        success: true,
        status: current[0].status,
        tx_hash: current[0].blockchain_tx_hash,
        message: "TX já registrada. Não será feito novo envio."
      };
    }

    await sql`
      UPDATE orders
      SET status = 'FAILED', updated_at = NOW()
      WHERE order_id = ${orderId}
        AND status = 'PAYMENT_CONFIRMED'
        AND blockchain_tx_hash IS NULL
    `;

    throw error;
  }
}

/* =========================================================
   HANDLER
========================================================= */

export default async function handler(req, res) {
  if (!adminSession(req)) {
    return res.status(401).json({
      success: false,
      message: "Sessão administrativa inválida."
    });
  }

  if (req.method !== "POST") {
    return res.status(405).json({
      success: false,
      message: "Método não permitido."
    });
  }

  try {
    const {
      action,
      purchase_order_id,
      withdrawal_id
    } = req.body || {};

    /* Binance automático */
    if (
      action === "admin_binance_transfer" &&
      purchase_order_id
    ) {
      return res.status(200).json(
        await processAdminPurchaseToBinanceInternal(
          purchase_order_id
        )
      );
    }

    /* Retirada normal */
    if (!withdrawal_id) {
      return res.status(400).json({
        success: false,
        message: "withdrawal_id obrigatório."
      });
    }

    const url = dbUrl();
    if (!url) throw new Error("Banco de dados não configurado.");

    const sql = neon(url);

    const rows = await sql`
      SELECT *
      FROM withdrawals
      WHERE id = ${withdrawal_id}
      LIMIT 1
    `;

    const withdrawal = rows[0];

    if (!withdrawal) {
      return res.status(404).json({
        success: false,
        message: "Levantamento não encontrado."
      });
    }

    if (
      String(withdrawal.status).toUpperCase() !== "AUTHORIZED"
    ) {
      return res.status(400).json({
        success: false,
        message: `Estado inválido: ${withdrawal.status}`
      });
    }

    const locked = await sql`
      UPDATE withdrawals
      SET status = 'PROCESSING', updated_at = NOW()
      WHERE id = ${withdrawal_id}
        AND status = 'AUTHORIZED'
      RETURNING id
    `;

    if (!locked[0]) {
      return res.status(409).json({
        success: false,
        message: "Este levantamento já está sendo processado."
      });
    }

    try {
      const amount =
        Number(withdrawal.amount_to_send || withdrawal.amount);

      const tx = await sendUSDT(
        withdrawal.destination_address,
        amount
      );

      await sql`
        UPDATE withdrawals
        SET tx_hash = ${tx.txHash},
            status = 'PROCESSING',
            updated_at = NOW()
        WHERE id = ${withdrawal_id}
          AND tx_hash IS NULL
      `;

      const check = await verifyTransaction(
        tx.txHash,
        withdrawal.destination_address,
        amount
      );

      if (check.confirmed) {
        await sql`
          UPDATE withdrawals
          SET status = 'COMPLETED',
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

      return res.status(200).json({
        success: true,
        status: "PROCESSING",
        tx_hash: tx.txHash,
        message: "TX enviada. Aguardar confirmação da TRON."
      });

    } catch (error) {
      const current = await sql`
        SELECT status, tx_hash
        FROM withdrawals
        WHERE id = ${withdrawal_id}
        LIMIT 1
      `;

      if (current[0]?.tx_hash) {
        return res.status(200).json({
          success: true,
          status: current[0].status,
          tx_hash: current[0].tx_hash,
          message: "TX já registrada. Não repetir."
        });
      }

      await sql`
        UPDATE withdrawals
        SET status = 'FAILED', updated_at = NOW()
        WHERE id = ${withdrawal_id}
          AND tx_hash IS NULL
      `;

      return res.status(500).json({
        success: false,
        status: "FAILED",
        message: error.message || "Erro na transferência."
      });
    }

  } catch (error) {
    console.error("ADMIN WITHDRAWAL PROCESS:", error);

    return res.status(500).json({
      success: false,
      message: error.message || "Erro interno."
    });
  }
}
