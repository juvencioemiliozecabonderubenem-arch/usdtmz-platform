import { neon } from "@neondatabase/serverless";
import {
  createHmac,
  timingSafeEqual
} from "node:crypto";

const sql = neon(process.env.DATABASE_URL);

const COOKIE_NAME = "usdtmz_admin_session";

const USDT_CONTRACT =
  "TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t";

const TRON_NETWORK = "TRON";

function json(res, status, data) {
  return res.status(status).json(data);
}

function safeCompare(a, b) {
  const A = Buffer.from(String(a));
  const B = Buffer.from(String(b));

  if (A.length !== B.length) {
    return false;
  }

  return timingSafeEqual(A, B);
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

function verifyAdminSession(req) {
  const secret =
    process.env.ADMIN_SESSION_SECRET;

  if (!secret) {
    return false;
  }

  const token =
    getSessionToken(req);

  if (!token) {
    return false;
  }

  const parts = token.split(".");

  if (parts.length !== 2) {
    return false;
  }

  const [data, signature] = parts;

  const expectedSignature =
    createHmac("sha256", secret)
      .update(data)
      .digest("base64url");

  if (
    !safeCompare(
      signature,
      expectedSignature
    )
  ) {
    return false;
  }

  try {
    const payload =
      JSON.parse(
        Buffer.from(
          data,
          "base64url"
        ).toString("utf8")
      );

    if (!payload.exp) {
      return false;
    }

    if (
      Date.now() >
      Number(payload.exp)
    ) {
      return false;
    }

    if (payload.id !== "admin") {
      return false;
    }

    return true;
  } catch {
    return false;
  }
}

function normalizeNumber(value) {
  const number = Number(value);

  return Number.isFinite(number)
    ? number
    : 0;
}

function normalizeAsset(asset) {
  return String(
    asset || ""
  )
    .trim()
    .toUpperCase();
}

function normalizeStatus(status) {
  return String(
    status || ""
  )
    .trim()
    .toUpperCase();
}

function maskAddress(address) {
  if (!address) {
    return "—";
  }

  const value =
    String(address);

  if (value.length <= 12) {
    return value;
  }

  return `${value.slice(
    0,
    6
  )}...${value.slice(-6)}`;
}

function isMainCompanyWallet(wallet) {
  const configuredAddress =
    process.env.USDTMZ_TRON_WALLET_ADDRESS;

  if (!configuredAddress) {
    return false;
  }

  return (
    String(
      wallet.wallet_address || ""
    ).trim() ===
    String(
      configuredAddress
    ).trim()
  );
}

function classifyWallet(wallet) {
  const asset =
    normalizeAsset(
      wallet.asset
    );

  const network =
    String(
      wallet.network || ""
    ).toUpperCase();

  if (asset === "USDT") {
    return "USDT";
  }

  if (
    asset === "MZN" ||
    asset === "MZN_BALANCE" ||
    asset === "MZN_RESERVE"
  ) {
    return "MZN";
  }

  if (
    asset === "TRX" ||
    (
      network === "TRON" &&
      asset === "TRX"
    )
  ) {
    return "TRX";
  }

  return asset || "UNKNOWN";
}

function transactionTypeLabel(type) {
  const value =
    String(type || "")
      .trim()
      .toUpperCase();

  const labels = {
    DEPOSIT: "Depósito",
    DEPOSIT_MZN: "Depósito MZN",
    DEPOSIT_USDT: "Depósito USDT",
    WITHDRAWAL: "Levantamento",
    WITHDRAW: "Envio",
    SEND: "Envio",
    RECEIVE: "Recebimento",
    PURCHASE: "Compra",
    BUY: "Compra USDT",
    SELL: "Venda",
    CONVERSION: "Conversão",
    CONVERT: "Conversão",
    TRANSFER: "Transferência",
    RESERVE_IN: "Entrada na reserva",
    RESERVE_OUT: "Saída da reserva",
    FEE: "Taxa"
  };

  return (
    labels[value] ||
    value ||
    "Operação"
  );
}

export default async function handler(
  req,
  res
) {
  try {
    if (!verifyAdminSession(req)) {
      return json(res, 401, {
        ok: false,
        error: "Não autorizado."
      });
    }

    if (req.method !== "GET") {
      res.setHeader(
        "Allow",
        "GET"
      );

      return json(res, 405, {
        ok: false,
        error:
          "Método não permitido."
      });
    }

    /*
     * =====================================================
     * CARTEIRAS
     * =====================================================
     */

    const wallets =
      await sql`
        SELECT
          id,
          wallet_address,
          network,
          asset,
          balance,
          status,
          created_at,
          updated_at,
          user_id
        FROM wallets
        ORDER BY
          updated_at DESC NULLS LAST,
          id DESC
      `;

    let reserveUSDT = 0;
    let reserveTRX = 0;
    let reserveMZN = 0;

    for (const wallet of wallets) {
      const asset =
        classifyWallet(wallet);

      if (
        isMainCompanyWallet(
          wallet
        )
      ) {
        if (asset === "USDT") {
          reserveUSDT +=
            normalizeNumber(
              wallet.balance
            );
        }

        if (asset === "TRX") {
          reserveTRX +=
            normalizeNumber(
              wallet.balance
            );
        }
      }

      if (
        asset === "MZN" &&
        (
          !wallet.status ||
          normalizeStatus(
            wallet.status
          ) === "ACTIVE" ||
          normalizeStatus(
            wallet.status
          ) === "AVAILABLE"
        )
      ) {
        reserveMZN +=
          normalizeNumber(
            wallet.balance
          );
      }
    }

    /*
     * =====================================================
     * TRANSAÇÕES
     * =====================================================
     */

    const transactions =
      await sql`
        SELECT
          id,
          user_id,
          type,
          asset,
          amount,
          status,
          reference,
          blockchain_tx_hash,
          created_at
        FROM transactions
        ORDER BY
          created_at DESC NULLS LAST,
          id DESC
        LIMIT 500
      `;

    const reserveTransactions =
      transactions
        .filter((tx) => {
          const asset =
            normalizeAsset(
              tx.asset
            );

          return (
            asset === "MZN" ||
            asset === "MZN_RESERVE" ||
            asset === "MZN_BALANCE" ||
            asset === "USDT"
          );
        })
        .map((tx) => ({
          id: tx.id,
          user_id: tx.user_id,
          type: tx.type,
          type_label:
            transactionTypeLabel(
              tx.type
            ),
          asset:
            normalizeAsset(
              tx.asset
            ),
          amount:
            normalizeNumber(
              tx.amount
            ),
          status:
            normalizeStatus(
              tx.status
            ),
          reference:
            tx.reference || null,
          blockchain_tx_hash:
            tx.blockchain_tx_hash ||
            null,
          created_at:
            tx.created_at
        }));

    /*
     * =====================================================
     * RETIRADAS
     * =====================================================
     */

    const withdrawals =
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
          order_id,
          amount_requested,
          withdrawal_fee,
          amount_to_send
        FROM withdrawals
        ORDER BY
          created_at DESC NULLS LAST,
          id DESC
        LIMIT 500
      `;

    const normalWithdrawals =
      withdrawals.map(
        (item) => ({
          id: item.id,

          type: "WITHDRAWAL",

          source:
            "USER_WITHDRAWAL",

          withdrawal_id:
            item.withdrawal_id ||
            null,

          user_id:
            item.user_id ||
            null,

          amount:
            normalizeNumber(
              item.amount_requested ??
              item.amount_to_send ??
              item.amount
            ),

          amount_requested:
            normalizeNumber(
              item.amount_requested
            ),

          withdrawal_fee:
            normalizeNumber(
              item.withdrawal_fee
            ),

          amount_to_send:
            normalizeNumber(
              item.amount_to_send
            ),

          asset:
            normalizeAsset(
              item.asset
            ),

          network:
            item.network ||
            null,

          destination_address:
            maskAddress(
              item.destination_address
            ),

          destination_label:
            item.destination_address ||
            "—",

          status:
            normalizeStatus(
              item.status
            ),

          tx_hash:
            item.tx_hash ||
            null,

          order_id:
            item.order_id ||
            null,

          created_at:
            item.created_at ||
            null,

          updated_at:
            item.updated_at ||
            null,

          is_binance: false
        })
      );

    /*
     * =====================================================
     * ORDERS → BINANCE
     * =====================================================
     */

    const orders =
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
          blockchain_tx_hash,
          wallet_address,
          pagar_payment_id,
          pagar_event_id,
          created_at,
          updated_at
        FROM orders
        WHERE operation =
          'BUY_USDT_ADMIN'
        ORDER BY
          created_at DESC NULLS LAST,
          id DESC
        LIMIT 500
      `;

    const binanceTransfers =
      orders.map(
        (order) => ({
          id:
            `BINANCE-${order.id}`,

          type:
            "BINANCE_TRANSFER",

          source:
            "ADMIN_PURCHASE",

          order_id:
            order.order_id,

          name:
            order.name,

          phone:
            order.phone,

          amount:
            normalizeNumber(
              order.usdt_amount
            ),

          amount_mzn:
            normalizeNumber(
              order.amount
            ),

          usdt_amount:
            normalizeNumber(
              order.usdt_amount
            ),

          rate:
            normalizeNumber(
              order.rate
            ),

          asset: "USDT",

          network:
            TRON_NETWORK,

          destination_address:
            "BINANCE TRC-20",

          destination_label:
            "Binance / TRON TRC-20",

          status:
            normalizeStatus(
              order.status
            ),

          tx_hash:
            order.blockchain_tx_hash ||
            null,

          wallet_address:
            order.wallet_address ||
            null,

          pagar_payment_id:
            order.pagar_payment_id ||
            null,

          pagar_event_id:
            order.pagar_event_id ||
            null,

          payment:
            order.payment ||
            null,

          operation:
            order.operation,

          created_at:
            order.created_at ||
            null,

          updated_at:
            order.updated_at ||
            null,

          is_binance: true
        })
      );

    /*
     * =====================================================
     * RESERVA USDT
     * =====================================================
     */

    const reservedUSDT =
      binanceTransfers
        .filter((item) => {
          return [
            "PROCESSING",
            "AUTHORIZED"
          ].includes(
            item.status
          );
        })
        .reduce(
          (
            total,
            item
          ) =>
            total +
            normalizeNumber(
              item.usdt_amount
            ),
          0
        );

    const availableUSDT =
      Math.max(
        0,
        reserveUSDT -
        reservedUSDT
      );

    /*
     * =====================================================
     * HISTÓRICO
     * =====================================================
     */

    const history = [
      ...normalWithdrawals.map(
        (item) => ({
          ...item,
          history_type:
            "WITHDRAWAL"
        })
      ),

      ...binanceTransfers.map(
        (item) => ({
          ...item,
          history_type:
            "BINANCE_TRANSFER"
        })
      ),

      ...reserveTransactions.map(
        (item) => ({
          ...item,
          history_type:
            "RESERVE_TRANSACTION"
        })
      )
    ]
      .sort(
        (a, b) => {
          const dateA =
            new Date(
              a.created_at ||
              0
            ).getTime();

          const dateB =
            new Date(
              b.created_at ||
              0
            ).getTime();

          return (
            dateB -
            dateA
          );
        }
      )
      .slice(
        0,
        1000
      );

    /*
     * =====================================================
     * CONTADORES
     * =====================================================
     */

    const pendingWithdrawals =
      normalWithdrawals
        .filter((item) =>
          [
            "PENDING",
            "AUTHORIZED",
            "PROCESSING"
          ].includes(
            item.status
          )
        ).length;

    const processingBinance =
      binanceTransfers
        .filter(
          (item) =>
            item.status ===
            "PROCESSING"
        ).length;

    const completedBinance =
      binanceTransfers
        .filter(
          (item) =>
            [
              "PAID",
              "COMPLETED"
            ].includes(
              item.status
            )
        ).length;

    const failedBinance =
      binanceTransfers
        .filter(
          (item) =>
            [
              "FAILED",
              "CANCELLED"
            ].includes(
              item.status
            )
        ).length;

    /*
     * =====================================================
     * RESPOSTA
     * =====================================================
     */

    return json(res, 200, {
      ok: true,

      reserve: {
        currency_fiat: "MZN",

        currency_crypto:
          "USDT",

        mzn: {
          balance:
            reserveMZN,

          available:
            reserveMZN
        },

        usdt: {
          balance:
            reserveUSDT,

          reserved:
            reservedUSDT,

          available:
            availableUSDT,

          contract:
            USDT_CONTRACT,

          network:
            TRON_NETWORK
        },

        trx: {
          balance:
            reserveTRX,

          network:
            TRON_NETWORK
        },

        company_wallet: {
          configured:
            Boolean(
              process.env
                .USDTMZ_TRON_WALLET_ADDRESS
            ),

          address:
            process.env
              .USDTMZ_TRON_WALLET_ADDRESS
              ? maskAddress(
                  process.env
                    .USDTMZ_TRON_WALLET_ADDRESS
                )
              : null,

          network:
            TRON_NETWORK
        }
      },

      wallets:
        wallets.map(
          (wallet) => ({
            id: wallet.id,

            asset:
              normalizeAsset(
                wallet.asset
              ),

            balance:
              normalizeNumber(
                wallet.balance
              ),

            status:
              normalizeStatus(
                wallet.status
              ),

            network:
              wallet.network ||
              null,

            wallet_address:
              maskAddress(
                wallet.wallet_address
              ),

            is_company_wallet:
              isMainCompanyWallet(
                wallet
              ),

            created_at:
              wallet.created_at ||
              null,

            updated_at:
              wallet.updated_at ||
              null
          })
        ),

      withdrawals:
        normalWithdrawals,

      normal_withdrawals:
        normalWithdrawals,

      binance_transfers:
        binanceTransfers,

      reserve_transactions:
        reserveTransactions,

      history,

      counts: {
        wallets:
          wallets.length,

        withdrawals:
          normalWithdrawals.length,

        binance_transfers:
          binanceTransfers.length,

        reserve_transactions:
          reserveTransactions.length,

        pending_withdrawals:
          pendingWithdrawals,

        processing_binance:
          processingBinance,

        completed_binance:
          completedBinance,

        failed_binance:
          failedBinance
      },

      system: {
        reserve_control:
          true,

        real_usdt_required:
          true,

        fake_usdt_creation:
          false,

        usdt_contract:
          USDT_CONTRACT,

        network:
          TRON_NETWORK,

        rate: 64,

        minimum_mzn: 64,

        maximum_mzn: 40000
      }
    });
  } catch (error) {
    console.error(
      "ADMIN WITHDRAWALS / RESERVE ERROR:",
      error
    );

    return json(res, 500, {
      ok: false,
      error:
        "Erro interno ao carregar a reserva."
    });
  }
}
