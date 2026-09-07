import { neon } from "@neondatabase/serverless";
import {
  createHmac,
  createHash,
  timingSafeEqual
} from "node:crypto";

const sql = neon(process.env.DATABASE_URL);

const COOKIE_NAME = "usdtmz_admin_session";

const USDT_CONTRACT =
  "TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t";

const TRON_NETWORK = "TRON";

const USDT_DECIMALS = 6;

const TRANSFER_TOPIC =
  "ddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef";

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
    createHmac(
      "sha256",
      secret
    )
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

    if (!payload) {
      return false;
    }

    if (payload.id !== "admin") {
      return false;
    }

    if (!payload.email) {
      return false;
    }

    if (!payload.exp) {
      return false;
    }

    const expiresAt =
      Number(payload.exp);

    if (!Number.isFinite(expiresAt)) {
      return false;
    }

    if (
      Date.now() >=
      expiresAt
    ) {
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
  return String(asset || "")
    .trim()
    .toUpperCase();
}

function normalizeStatus(status) {
  return String(status || "")
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

function isValidTxHash(txHash) {
  return /^[a-fA-F0-9]{64}$/.test(
    String(txHash || "").trim()
  );
}

function isValidTronAddress(address) {
  return /^T[1-9A-HJ-NP-Za-km-z]{33}$/.test(
    String(address || "").trim()
  );
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
    ).trim()
    .toUpperCase();

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
    asset === "TRX" &&
    network === "TRON"
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
    DEPOSIT:
      "Depósito",

    DEPOSIT_MZN:
      "Depósito MZN",

    DEPOSIT_USDT:
      "Depósito USDT",

    WITHDRAWAL:
      "Levantamento",

    WITHDRAW:
      "Envio",

    SEND:
      "Envio",

    RECEIVE:
      "Recebimento",

    PURCHASE:
      "Compra",

    BUY:
      "Compra USDT",

    SELL:
      "Venda",

    CONVERSION:
      "Conversão",

    CONVERT:
      "Conversão",

    TRANSFER:
      "Transferência",

    RESERVE_IN:
      "Entrada na reserva",

    RESERVE_OUT:
      "Saída da reserva",

    FEE:
      "Taxa"
  };

  return (
    labels[value] ||
    value ||
    "Operação"
  );
}

function getTronBaseUrl() {
  return (
    process.env.TRON_API_BASE_URL ||
    "https://api.trongrid.io"
  ).replace(/\/+$/, "");
}

function getTronApiKey() {
  return process.env.TRON_PRO_API_KEY;
}

async function tronPost(
  path,
  body
) {
  const apiKey =
    getTronApiKey();

  if (!apiKey) {
    throw new Error(
      "TRON_PRO_API_KEY não configurado."
    );
  }

  const response =
    await fetch(
      `${getTronBaseUrl()}${path}`,
      {
        method: "POST",

        headers: {
          "Content-Type":
            "application/json",

          Accept:
            "application/json",

          "TRON-PRO-API-KEY":
            apiKey
        },

        body:
          JSON.stringify(body)
      }
    );

  const text =
    await response.text();

  let data;

  try {
    data =
      JSON.parse(text);
  } catch {
    throw new Error(
      "Resposta inválida da TRON."
    );
  }

  if (!response.ok) {
    throw new Error(
      data?.Error ||
      data?.message ||
      `TRON HTTP ${response.status}`
    );
  }

  return data;
}

function doubleSha256(buffer) {
  const first =
    createHash("sha256")
      .update(buffer)
      .digest();

  return createHash("sha256")
    .update(first)
    .digest();
}

function base58Decode(value) {
  const alphabet =
    "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

  let number = 0n;

  for (
    const character of
    String(value)
  ) {
    const index =
      alphabet.indexOf(
        character
      );

    if (index < 0) {
      throw new Error(
        "Endereço TRON inválido."
      );
    }

    number =
      number * 58n +
      BigInt(index);
  }

  let hex =
    number.toString(16);

  if (
    hex.length % 2 !== 0
  ) {
    hex =
      `0${hex}`;
  }

  let bytes =
    Buffer.from(
      hex,
      "hex"
    );

  let leadingZeros = 0;

  for (
    const character of
    String(value)
  ) {
    if (
      character === "1"
    ) {
      leadingZeros++;
    } else {
      break;
    }
  }

  if (leadingZeros > 0) {
    bytes =
      Buffer.concat([
        Buffer.alloc(
          leadingZeros
        ),
        bytes
      ]);
  }

  return bytes;
}

function tronAddressToHex(
  address
) {
  if (
    !isValidTronAddress(
      address
    )
  ) {
    throw new Error(
      "Endereço TRON inválido."
    );
  }

  const decoded =
    base58Decode(
      address
    );

  if (
    decoded.length !== 25
  ) {
    throw new Error(
      "Endereço TRON inválido."
    );
  }

  const payload =
    decoded.subarray(
      0,
      21
    );

  const checksum =
    decoded.subarray(
      21,
      25
    );

  const expectedChecksum =
    doubleSha256(
      payload
    ).subarray(
      0,
      4
    );

  if (
    !timingSafeEqual(
      checksum,
      expectedChecksum
    )
  ) {
    throw new Error(
      "Checksum do endereço TRON inválido."
    );
  }

  return payload
    .toString("hex")
    .toUpperCase();
}

function tronContractToLogAddress(
  address
) {
  return tronAddressToHex(
    address
  )
    .replace(/^41/, "")
    .toLowerCase();
}

function decodeTopicAddress(
  topic
) {
  const value =
    String(topic || "")
      .replace(/^0x/i, "")
      .toLowerCase();

  if (
    !/^[0-9a-f]{64}$/.test(
      value
    )
  ) {
    return null;
  }

  const addressHex =
    `41${value.slice(-40)}`;

  const payload =
    Buffer.from(
      addressHex,
      "hex"
    );

  const checksum =
    doubleSha256(
      payload
    ).subarray(
      0,
      4
    );

  const full =
    Buffer.concat([
      payload,
      checksum
    ]);

  const alphabet =
    "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

  let number = 0n;

  for (
    const byte of full
  ) {
    number =
      number * 256n +
      BigInt(byte);
  }

  let encoded = "";

  while (
    number > 0n
  ) {
    const remainder =
      Number(
        number % 58n
      );

    encoded =
      alphabet[remainder] +
      encoded;

    number =
      number / 58n;
  }

  for (
    const byte of full
  ) {
    if (byte === 0) {
      encoded =
        `1${encoded}`;
    } else {
      break;
    }
  }

  return encoded;
}

function decodeUint256(
  data
) {
  const value =
    String(data || "")
      .replace(/^0x/i, "")
      .trim();

  if (
    !/^[0-9a-fA-F]+$/.test(
      value
    )
  ) {
    throw new Error(
      "Valor USDT inválido."
    );
  }

  return BigInt(
    `0x${value}`
  );
}

function rawUSDTToNumber(
  raw
) {
  const base =
    10n ** BigInt(
      USDT_DECIMALS
    );

  const whole =
    raw / base;

  const fraction =
    raw % base;

  return (
    Number(whole) +
    Number(fraction) /
      Number(base)
  );
}

async function getSolidifiedReceipt(
  txHash
) {
  return tronPost(
    "/walletsolidity/gettransactioninfobyid",
    {
      value:
        txHash
    }
  );
}

async function verifyUSDTDeposit(
  txHash,
  companyAddress,
  requestedAmount
) {
  if (
    !isValidTxHash(
      txHash
    )
  ) {
    throw new Error(
      "TX Hash TRON inválido."
    );
  }

  if (
    !isValidTronAddress(
      companyAddress
    )
  ) {
    throw new Error(
      "Carteira da tesouraria inválida."
    );
  }

  const receipt =
    await getSolidifiedReceipt(
      txHash
    );

  if (
    !receipt ||
    String(
      receipt.id || ""
    ).toLowerCase() !==
      txHash.toLowerCase()
  ) {
    throw new Error(
      "A transação ainda não possui receipt solidificado na TRON."
    );
  }

  if (
    receipt.result ===
    "FAILED"
  ) {
    throw new Error(
      "A transação TRON falhou."
    );
  }

  const executionResult =
    String(
      receipt.receipt?.result ||
      ""
    ).toUpperCase();

  if (
    executionResult !==
    "SUCCESS"
  ) {
    throw new Error(
      `A execução da transação não foi concluída com sucesso (${executionResult || "SEM RESULTADO"}).`
    );
  }

  const logs =
    Array.isArray(
      receipt.log
    )
      ? receipt.log
      : [];

  const contractLogAddress =
    tronContractToLogAddress(
      USDT_CONTRACT
    );

  const destinationHex =
    tronAddressToHex(
      companyAddress
    )
      .replace(/^41/, "")
      .toLowerCase();

  const expectedAmount =
    Number(
      requestedAmount
    );

  let confirmedAmount = 0;
  let sender = null;

  for (
    const log of logs
  ) {
    const logAddress =
      String(
        log.address || ""
      )
        .replace(/^41/i, "")
        .toLowerCase();

    if (
      logAddress !==
      contractLogAddress
    ) {
      continue;
    }

    const topics =
      Array.isArray(
        log.topics
      )
        ? log.topics
        : [];

    if (
      topics.length < 3
    ) {
      continue;
    }

    const topic0 =
      String(
        topics[0] || ""
      )
        .replace(
          /^0x/i,
          ""
        )
        .toLowerCase();

    if (
      topic0 !==
      TRANSFER_TOPIC
    ) {
      continue;
    }

    const fromHex =
      String(
        topics[1] || ""
      )
        .replace(
          /^0x/i,
          ""
        )
        .toLowerCase()
        .slice(-40);

    const toHex =
      String(
        topics[2] || ""
      )
        .replace(
          /^0x/i,
          ""
        )
        .toLowerCase()
        .slice(-40);

    if (
      toHex !==
      destinationHex
    ) {
      continue;
    }

    const rawValue =
      decodeUint256(
        log.data
      );

    const amount =
      rawUSDTToNumber(
        rawValue
      );

    if (
      amount <= 0
    ) {
      continue;
    }

    sender =
      decodeTopicAddress(
        topics[1]
      );

    confirmedAmount +=
      amount;
  }

  if (
    confirmedAmount <= 0
  ) {
    throw new Error(
      "Nenhuma transferência USDT TRC-20 confirmada para a carteira da tesouraria foi encontrada."
    );
  }

  if (
    confirmedAmount <
    expectedAmount
  ) {
    throw new Error(
      `A blockchain confirmou ${confirmedAmount} USDT, abaixo dos ${expectedAmount} USDT informados.`
    );
  }

  return {
    tx_hash:
      txHash,

    amount_usdt:
      confirmedAmount,

    from:
      sender,

    to:
      companyAddress,

    contract:
      USDT_CONTRACT,

    network:
      TRON_NETWORK,

    block_number:
      receipt.blockNumber ||
      null,

    confirmed:
      true
  };
}

async function registerRealUSDTDeposit(
  req,
  res
) {
  const body =
    req.body || {};

  const txHash =
    String(
      body.tx_hash ||
      body.txHash ||
      ""
    ).trim();

  const requestedAmount =
    Number(
      body.amount_usdt ??
      body.amount ??
      0
    );

  if (
    !txHash
  ) {
    return json(res, 400, {
      ok: false,
      error:
        "TX Hash é obrigatório."
    });
  }

  if (
    !Number.isFinite(
      requestedAmount
    ) ||
    requestedAmount <= 0
  ) {
    return json(res, 400, {
      ok: false,
      error:
        "Valor USDT inválido."
    });
  }

  if (
    !process.env.USDTMZ_TRON_WALLET_ADDRESS
  ) {
    return json(res, 500, {
      ok: false,
      error:
        "USDTMZ_TRON_WALLET_ADDRESS não configurado."
    });
  }

  const companyAddress =
    String(
      process.env
        .USDTMZ_TRON_WALLET_ADDRESS
    ).trim();

  if (
    !isValidTronAddress(
      companyAddress
    )
  ) {
    return json(res, 500, {
      ok: false,
      error:
        "Endereço da tesouraria TRON inválido."
    });
  }

  /*
   * Primeiro verificamos se a TX já
   * entrou no ledger.
   */
  const alreadyRegistered =
    await sql`
      SELECT
        id,
        type,
        asset,
        amount,
        status,
        reference,
        blockchain_tx_hash,
        created_at
      FROM transactions
      WHERE blockchain_tx_hash =
        ${txHash}
      LIMIT 1
    `;

  if (
    alreadyRegistered.length
  ) {
    return json(res, 409, {
      ok: false,
      error:
        "Esta TX Hash já está registrada na tesouraria.",
      transaction:
        alreadyRegistered[0]
    });
  }

  /*
   * Confirmação REAL na blockchain.
   */
  const verified =
    await verifyUSDTDeposit(
      txHash,
      companyAddress,
      requestedAmount
    );

  /*
   * =====================================================
   * TRANSAÇÃO ATÔMICA DO LEDGER
   * =====================================================
   *
   * O advisory lock usa a própria TX como
   * chave lógica. Assim duas requisições
   * simultâneas para a mesma TX não podem
   * contabilizar o depósito duas vezes.
   */

  const transactionReference =
    `RESERVE_USDT:${txHash}`;

  const transactionResults =
    await sql.transaction(
      (txn) => [
        txn`
          SELECT
            pg_advisory_xact_lock(
              hashtext(${txHash})
            )
        `,

        txn`
          SELECT
            id
          FROM transactions
          WHERE
            blockchain_tx_hash =
              ${txHash}
          LIMIT 1
        `,

        txn`
          INSERT INTO transactions (
            user_id,
            type,
            asset,
            amount,
            status,
            reference,
            blockchain_tx_hash,
            created_at
          )
          SELECT
            NULL,
            'DEPOSIT_USDT',
            'USDT',
            ${verified.amount_usdt},
            'COMPLETED',
            ${transactionReference},
            ${txHash},
            NOW()
          WHERE NOT EXISTS (
            SELECT 1
            FROM transactions
            WHERE
              blockchain_tx_hash =
                ${txHash}
          )
          RETURNING
            id,
            type,
            asset,
            amount,
            status,
            reference,
            blockchain_tx_hash,
            created_at
        `,

        txn`
          UPDATE wallets
          SET
            balance =
              balance +
              ${verified.amount_usdt},
            status =
              'ACTIVE',
            updated_at =
              NOW()
          WHERE
            wallet_address =
              ${companyAddress}
            AND network =
              ${TRON_NETWORK}
            AND asset =
              'USDT'
          RETURNING
            id,
            wallet_address,
            network,
            asset,
            balance,
            status,
            updated_at
        `
      ],
      {
        isolationMode:
          "Serializable"
      }
    );

  const transactionInsert =
    transactionResults[2] || [];

  const walletUpdate =
    transactionResults[3] || [];

  /*
   * Se já havia TX registrada, nada
   * mais deve ser contabilizado.
   */
  if (
    transactionInsert.length === 0
  ) {
    return json(res, 409, {
      ok: false,
      error:
        "Esta TX já foi registrada por outra operação."
    });
  }

  /*
   * A carteira USDT da empresa precisa
   * existir no ledger.
   *
   * Não criamos uma carteira silenciosamente
   * durante um depósito financeiro.
   */
  if (
    walletUpdate.length === 0
  ) {
    return json(res, 500, {
      ok: false,
      error:
        "A carteira USDT/TRON da tesouraria não existe no ledger. Nenhum saldo foi confirmado."
    });
  }

  const previousBalance =
    normalizeNumber(
      walletUpdate[0].balance
    ) -
    verified.amount_usdt;

  return json(res, 200, {
    ok: true,

    message:
      "Depósito USDT confirmado na blockchain e registrado na reserva real.",

    deposit: {
      tx_hash:
        verified.tx_hash,

      amount_usdt:
        verified.amount_usdt,

      from:
        verified.from,

      to:
        verified.to,

      contract:
        verified.contract,

      network:
        verified.network,

      block_number:
        verified.block_number,

      status:
        "COMPLETED"
    },

    reserve: {
      previous_balance:
        previousBalance,

      added:
        verified.amount_usdt,

      new_balance:
        normalizeNumber(
          walletUpdate[0].balance
        )
    },

    transaction:
      transactionInsert[0]
  });
}

async function loadDashboard(
  req,
  res
) {
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

  for (
    const wallet of
    wallets
  ) {
    const asset =
      classifyWallet(
        wallet
      );

    if (
      isMainCompanyWallet(
        wallet
      )
    ) {
      if (
        asset === "USDT"
      ) {
        reserveUSDT +=
          normalizeNumber(
            wallet.balance
          );
      }

      if (
        asset === "TRX"
      ) {
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
        [
          "ACTIVE",
          "AVAILABLE"
        ].includes(
          normalizeStatus(
            wallet.status
          )
        )
      )
    ) {
      reserveMZN +=
        normalizeNumber(
          wallet.balance
        );
    }
  }

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
      .filter(
        (tx) => {
          const asset =
            normalizeAsset(
              tx.asset
            );

          return [
            "MZN",
            "MZN_RESERVE",
            "MZN_BALANCE",
            "USDT"
          ].includes(
            asset
          );
        }
      )
      .map(
        (tx) => ({
          id:
            tx.id,

          user_id:
            tx.user_id,

          type:
            tx.type,

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
            tx.reference ||
            null,

          blockchain_tx_hash:
            tx.blockchain_tx_hash ||
            null,

          created_at:
            tx.created_at
        })
      );

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
        id:
          item.id,

        type:
          "WITHDRAWAL",

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

        is_binance:
          false
      })
    );

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

        asset:
          "USDT",

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

        is_binance:
          true
      })
    );

  const reservedUSDT =
    binanceTransfers
      .filter(
        (item) =>
          [
            "PROCESSING",
            "AUTHORIZED"
          ].includes(
            item.status
          )
      )
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
      (a, b) =>
        new Date(
          b.created_at || 0
        ).getTime() -
        new Date(
          a.created_at || 0
        ).getTime()
    )
    .slice(
      0,
      1000
    );

  const pendingWithdrawals =
    normalWithdrawals
      .filter(
        (item) =>
          [
            "PENDING",
            "AUTHORIZED",
            "PROCESSING"
          ].includes(
            item.status
          )
      )
      .length;

  const processingBinance =
    binanceTransfers
      .filter(
        (item) =>
          item.status ===
          "PROCESSING"
      )
      .length;

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
      )
      .length;

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
      )
      .length;

  return json(res, 200, {
    ok: true,

    reserve: {
      currency_fiat:
        "MZN",

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
          id:
            wallet.id,

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

      blockchain_verification:
        true,

      solidified_receipt:
        true,

      duplicate_tx_protection:
        true,

      atomic_ledger:
        true,

      usdt_contract:
        USDT_CONTRACT,

      network:
        TRON_NETWORK,

      rate:
        64,

      minimum_mzn:
        64,

      maximum_mzn:
        40000
    }
  });
}

export default async function handler(
  req,
  res
) {
  try {
    if (
      !verifyAdminSession(
        req
      )
    ) {
      return json(res, 401, {
        ok: false,
        error:
          "Não autorizado."
      });
    }

    if (
      req.method ===
      "GET"
    ) {
      return loadDashboard(
        req,
        res
      );
    }

    if (
      req.method ===
      "POST"
    ) {
      return registerRealUSDTDeposit(
        req,
        res
      );
    }

    res.setHeader(
      "Allow",
      "GET, POST"
    );

    return json(res, 405, {
      ok: false,
      error:
        "Método não permitido."
    });
  } catch (error) {
    console.error(
      "USDTMZ ADMIN TREASURY ERROR:",
      error
    );

    return json(res, 500, {
      ok: false,
      error:
        error?.message ||
        "Erro interno da tesouraria."
    });
  }
}
