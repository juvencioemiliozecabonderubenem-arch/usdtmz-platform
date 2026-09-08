import { neon } from "@neondatabase/serverless";
import { createHmac, timingSafeEqual } from "node:crypto";
import { TronWeb } from "tronweb";

const COOKIE = "usdtmz_admin_session";
const USDT = "TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t";
const FEE_LIMIT = 100_000_000;

const dbUrl = () =>
  process.env.URL_DO_BANCO_DE_DADOS ||
  process.env.POSTGRES_URL ||
  process.env.DATABASE_URL ||
  process.env.POSTGRES_URL_NON_POOLING ||
  process.env.DATABASE_URL_UNPOOLED;

const compare = (a, b) => {
  const A = Buffer.from(String(a)), B = Buffer.from(String(b));
  return A.length === B.length && timingSafeEqual(A, B);
};

function session(req) {
  const raw = req.headers.cookie || "";
  const item = raw.split(";").map(x => x.trim()).find(x => x.startsWith(`${COOKIE}=`));
  if (!item || !process.env.ADMIN_SESSION_SECRET) return null;

  const token = item.slice(COOKIE.length + 1).split(".");
  if (token.length !== 2) return null;

  const [data, sig] = token;
  const expected = createHmac("sha256", process.env.ADMIN_SESSION_SECRET)
    .update(data).digest("base64url");

  if (!compare(sig, expected)) return null;

  try {
    const p = JSON.parse(Buffer.from(data, "base64url").toString());
    return p.id === "admin" && Number(p.exp) > Date.now() ? p : null;
  } catch {
    return null;
  }
}

function getTron() {
  const privateKey = process.env.USDTMZ_TRON_PRIVATE_KEY;
  if (!privateKey) throw new Error("USDTMZ_TRON_PRIVATE_KEY não configurada.");

  const tron = new TronWeb({
    fullHost: "https://api.trongrid.io",
    privateKey
  });

  const address =
    process.env.USDTMZ_TRON_WALLET_ADDRESS ||
    tron.address.fromPrivateKey(privateKey);

  if (!tron.isAddress(address)) {
    throw new Error("Carteira TRON da tesouraria inválida.");
  }

  return { tron, address };
}

async function sendUSDT(to, amount) {
  const { tron, address } = getTron();

  if (!tron.isAddress(to)) throw new Error("Endereço TRON inválido.");

  const value = Math.round(Number(amount) * 1_000_000);
  if (!Number.isSafeInteger(value) || value <= 0) {
    throw new Error("Quantidade USDT inválida.");
  }

  const trx = Number(await tron.trx.getBalance(address)) / 1_000_000;
  if (trx <= 0) throw new Error("Saldo TRX insuficiente para pagar a rede.");

  const contract = await tron.contract().at(USDT);
  const result = await contract.transfer(to, value).send({
    feeLimit: FEE_LIMIT
  });

  if (!result) throw new Error("TRON não devolveu TX hash.");

  return String(result);
}

async function markProcessing(sql, orderId) {
  const rows = await sql`
    UPDATE orders
    SET status = 'PROCESSING', updated_at = NOW()
    WHERE order_id = ${orderId}
      AND status IN ('PAID', 'PROCESSING')
      AND blockchain_tx_hash IS NULL
    RETURNING order_id, usdt_amount, status
  `;
  return rows[0] || null;
}

async function markCompleted(sql, orderId, txHash) {
  await sql`
    UPDATE orders
    SET status = 'COMPLETED',
        blockchain_tx_hash = ${txHash},
        updated_at = NOW()
    WHERE order_id = ${orderId}
      AND blockchain_tx_hash IS NULL
  `;
}

async function markFailed(sql, orderId, message) {
  await sql`
    UPDATE orders
    SET status = 'FAILED',
        updated_at = NOW()
    WHERE order_id = ${orderId}
      AND blockchain_tx_hash IS NULL
      AND status <> 'PROCESSING'
  `;
  console.error("USDTMZ TRANSFER FAILED:", orderId, message);
}

/*
 * ==========================================================
 * API INTERNO USADO PELO CRIAR-COMPRA.JS
 * ==========================================================
 */
export async function processAdminPurchaseToBinanceInternal(orderId) {
  if (!orderId) throw new Error("orderId obrigatório.");

  const databaseUrl = dbUrl();
  if (!databaseUrl) throw new Error("Banco de dados não configurado.");

  const sql = neon(databaseUrl);

  const orders = await sql`
    SELECT order_id, usdt_amount, status, blockchain_tx_hash
    FROM orders
    WHERE order_id = ${orderId}
      AND operation = 'BUY_USDT_ADMIN'
    LIMIT 1
  `;

  const order = orders[0];
  if (!order) throw new Error("Compra não encontrada.");

  if (order.blockchain_tx_hash) {
    return {
      success: true,
      already_sent: true,
      tx_hash: order.blockchain_tx_hash
    };
  }

  if (!["PAID", "PROCESSING"].includes(String(order.status).toUpperCase())) {
    throw new Error(`Compra não está PAID. Estado atual: ${order.status}`);
  }

  const destination = process.env.BINANCE_USDT_TRON_ADDRESS;
  if (!destination) throw new Error("BINANCE_USDT_TRON_ADDRESS não configurado.");

  if (String(order.status).toUpperCase() === "PAID") {
    const locked = await markProcessing(sql, orderId);
    if (!locked) {
      const again = await sql`
        SELECT status, blockchain_tx_hash
        FROM orders WHERE order_id = ${orderId}
      `;
      if (again[0]?.blockchain_tx_hash) {
        return { success: true, already_sent: true, tx_hash: again[0].blockchain_tx_hash };
      }
    }
  }

  try {
    const txHash = await sendUSDT(destination, order.usdt_amount);

    await markCompleted(sql, orderId, txHash);

    return {
      success: true,
      status: "COMPLETED",
      tx_hash: txHash
    };
  } catch (error) {
    /*
     * Se a transmissão chegou à blockchain mas não sabemos
     * o resultado, NÃO marcamos como FAILED automaticamente.
     */
    console.error("BINANCE TRANSFER ERROR:", error);

    if (String(order.status).toUpperCase() === "PROCESSING") {
      return {
        success: false,
        status: "PROCESSING",
        message: "Transferência em processamento; verificar TX antes de repetir."
      };
    }

    await markFailed(sql, orderId, error?.message);
    throw error;
  }
}

/*
 * ==========================================================
 * HANDLER ADMIN — RETIRADAS NORMAIS + BINANCE MANUAL
 * ==========================================================
 */
export default async function handler(req, res) {
  const admin = session(req);

  if (!admin) {
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
    const { action, purchase_order_id, withdrawal_id } = req.body || {};

    /*
     * Envio manual de compra PAID para Binance.
     */
    if (
      action === "admin_binance_transfer" &&
      purchase_order_id
    ) {
      const result =
        await processAdminPurchaseToBinanceInternal(purchase_order_id);

      return res.status(200).json(result);
    }

    /*
     * Retirada normal.
     */
    if (!withdrawal_id) {
      return res.status(400).json({
        success: false,
        message: "withdrawal_id obrigatório."
      });
    }

    const databaseUrl = dbUrl();
    if (!databaseUrl) throw new Error("Banco de dados não configurado.");

    const sql = neon(databaseUrl);

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

    if (withdrawal.status !== "AUTHORIZED") {
      return res.status(400).json({
        success: false,
        message: `Estado inválido: ${withdrawal.status}`
      });
    }

    await sql`
      UPDATE withdrawals
      SET status = 'PROCESSING',
          updated_at = NOW()
      WHERE id = ${withdrawal_id}
        AND status = 'AUTHORIZED'
    `;

    try {
      const txHash = await sendUSDT(
        withdrawal.destination_address,
        withdrawal.amount_to_send || withdrawal.amount
      );

      await sql`
        UPDATE withdrawals
        SET status = 'COMPLETED',
            tx_hash = ${txHash},
            updated_at = NOW()
        WHERE id = ${withdrawal_id}
      `;

      return res.status(200).json({
        success: true,
        status: "COMPLETED",
        tx_hash: txHash
      });
    } catch (error) {
      console.error("WITHDRAWAL ERROR:", error);

      return res.status(500).json({
        success: false,
        status: "PROCESSING",
        message: "Transferência iniciada ou em verificação. Não repetir automaticamente."
      });
    }
  } catch (error) {
    console.error("ADMIN WITHDRAWAL PROCESS ERROR:", error);

    return res.status(500).json({
      success: false,
      message: error?.message || "Erro ao processar transferência."
    });
  }
}
