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

const RATE = 64;
const MIN_MZN = 64;
const MAX_MZN = 40000;

function json(res, status, data) {
  return res.status(status).json(data);
}

function safeCompare(a, b) {
  const A = Buffer.from(String(a));
  const B = Buffer.from(String(b));

  if (A.length !== B.length) return false;

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

  return cookie
    ? cookie.substring(COOKIE_NAME.length + 1)
    : null;
}

function verifyAdminSession(req) {
  const secret = process.env.ADMIN_SESSION_SECRET;
  if (!secret) return false;

  const token = getSessionToken(req);
  if (!token) return false;

  const parts = token.split(".");
  if (parts.length !== 2) return false;

  const [data, signature] = parts;

  const expectedSignature = createHmac(
    "sha256",
    secret
  )
    .update(data)
    .digest("base64url");

  if (!safeCompare(signature, expectedSignature)) {
    return false;
  }

  try {
    const payload = JSON.parse(
      Buffer.from(data, "base64url").toString("utf8")
    );

    if (
      !payload ||
      payload.id !== "admin" ||
      !payload.email ||
      !payload.exp
    ) {
      return false;
    }

    return Date.now() < Number(payload.exp);
  } catch {
    return false;
  }
}

function normalizeNumber(value) {
  const number = Number(value);
  return Number.isFinite(number) ? number : 0;
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
  if (!address) return "—";

  const value = String(address);

  if (value.length <= 12) return value;

  return `${value.slice(0, 6)}...${value.slice(-6)}`;
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

  if (!configuredAddress) return false;

  return (
    String(wallet.wallet_address || "").trim() ===
    String(configuredAddress).trim()
  );
}

function classifyWallet(wallet) {
  const asset = normalizeAsset(wallet.asset);

  const network = String(wallet.network || "")
    .trim()
    .toUpperCase();

  if (asset === "USDT") return "USDT";

  if (
    asset === "MZN" ||
    asset === "MZN_BALANCE" ||
    asset === "MZN_RESERVE"
  ) {
    return "MZN";
  }

  if (asset === "TRX" && network === "TRON") {
    return "TRX";
  }

  return asset || "UNKNOWN";
}

function transactionTypeLabel(type) {
  const value = String(type || "")
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

  return labels[value] || value || "Operação";
}

/* =========================================================
   TRON
========================================================= */

function getTronBaseUrl() {
  return (
    process.env.TRON_API_BASE_URL ||
    "https://api.trongrid.io"
  ).replace(/\/+$/, "");
}

function getTronApiKey() {
  return process.env.TRON_PRO_API_KEY;
}

async function tronPost(path, body) {
  const apiKey = getTronApiKey();

  if (!apiKey) {
    throw new Error(
      "TRON_PRO_API_KEY não configurado."
    );
  }

  const response = await fetch(
    `${getTronBaseUrl()}${path}`,
    {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Accept: "application/json",
        "TRON-PRO-API-KEY": apiKey
      },
      body: JSON.stringify(body)
    }
  );

  const text = await response.text();

  let data;

  try {
    data = JSON.parse(text);
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
  const first = createHash("sha256")
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

  for (const character of String(value)) {
    const index = alphabet.indexOf(character);

    if (index < 0) {
      throw new Error(
        "Endereço TRON inválido."
      );
    }

    number = number * 58n + BigInt(index);
  }

  let hex = number.toString(16);

  if (hex.length % 2 !== 0) {
    hex = `0${hex}`;
  }

  let bytes = Buffer.from(hex, "hex");

  let leadingZeros = 0;

  for (const character of String(value)) {
    if (character === "1") {
      leadingZeros++;
    } else {
      break;
    }
  }

  if (leadingZeros > 0) {
    bytes = Buffer.concat([
      Buffer.alloc(leadingZeros),
      bytes
    ]);
  }

  return bytes;
}

function tronAddressToHex(address) {
  if (!isValidTronAddress(address)) {
    throw new Error(
      "Endereço TRON inválido."
    );
  }

  const decoded = base58Decode(address);

  if (decoded.length !== 25) {
    throw new Error(
      "Endereço TRON inválido."
    );
  }

  const payload = decoded.subarray(0, 21);
  const checksum = decoded.subarray(21, 25);

  const expectedChecksum = doubleSha256(
    payload
  ).subarray(0, 4);

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

  return payload.toString("hex").toUpperCase();
}

function tronContractToLogAddress(address) {
  return tronAddressToHex(address)
    .replace(/^41/, "")
    .toLowerCase();
}

function decodeTopicAddress(topic) {
  const value = String(topic || "")
    .replace(/^0x/i, "")
    .toLowerCase();

  if (!/^[0-9a-f]{64}$/.test(value)) {
    return null;
  }

  const addressHex = `41${value.slice(-40)}`;
  const payload = Buffer.from(addressHex, "hex");

  const checksum = doubleSha256(payload)
    .subarray(0, 4);

  const full = Buffer.concat([
    payload,
    checksum
  ]);

  const alphabet =
    "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

  let number = 0n;

  for (const byte of full) {
    number = number * 256n + BigInt(byte);
  }

  let encoded = "";

  while (number > 0n) {
    const remainder = Number(number % 58n);
    encoded = alphabet[remainder] + encoded;
    number = number / 58n;
  }

  for (const byte of full) {
    if (byte === 0) {
      encoded = `1${encoded}`;
    } else {
      break;
    }
  }

  return encoded;
}

function decodeUint256(data) {
  const value = String(data || "")
    .replace(/^0x/i, "")
    .trim();

  if (!/^[0-9a-fA-F]+$/.test(value)) {
    throw new Error(
      "Valor USDT inválido."
    );
  }

  return BigInt(`0x${value}`);
}

function rawUSDTToNumber(raw) {
  const base = 10n ** BigInt(USDT_DECIMALS);
  const whole = raw / base;
  const fraction = raw % base;

  return (
    Number(whole) +
    Number(fraction) / Number(base)
  );
}

async function getSolidifiedReceipt(txHash) {
  return tronPost(
    "/walletsolidity/gettransactioninfobyid",
    {
      value: txHash
    }
  );
}

async function verifyUSDTDeposit(
  txHash,
  companyAddress,
  requestedAmount
) {
  if (!isValidTxHash(txHash)) {
    throw new Error(
      "TX Hash TRON inválido."
    );
  }

  if (!isValidTronAddress(companyAddress)) {
    throw new Error(
      "Carteira da tesouraria inválida."
    );
  }

  const receipt =
    await getSolidifiedReceipt(txHash);

  if (
    !receipt ||
    String(receipt.id || "").toLowerCase() !==
      txHash.toLowerCase()
  ) {
    throw new Error(
      "A transação ainda não possui receipt solidificado na TRON."
    );
  }

  if (
    String(receipt.result || "").toUpperCase() ===
    "FAILED"
  ) {
    throw new Error(
      "A transação TRON falhou."
    );
  }

  const executionResult = String(
    receipt.receipt?.result || ""
  ).toUpperCase();

  if (executionResult !== "SUCCESS") {
    throw new Error(
      `A execução da transação não foi concluída com sucesso (${executionResult || "SEM RESULTADO"}).`
    );
  }

  const logs = Array.isArray(receipt.log)
    ? receipt.log
    : [];

  const contractLogAddress =
    tronContractToLogAddress(
      USDT_CONTRACT
    );

  const destinationHex =
    tronAddressToHex(companyAddress)
      .replace(/^41/, "")
      .toLowerCase();

  const expectedAmount =
    Number(requestedAmount);

  let confirmedAmount = 0;
  let sender = null;

  for (const log of logs) {
    const logAddress = String(
      log.address || ""
    )
      .replace(/^41/i, "")
      .toLowerCase();

    if (logAddress !== contractLogAddress) {
      continue;
    }

    const topics = Array.isArray(log.topics)
      ? log.topics
      : [];

    if (topics.length < 3) continue;

    const topic0 = String(topics[0] || "")
      .replace(/^0x/i, "")
      .toLowerCase();

    if (topic0 !== TRANSFER_TOPIC) {
      continue;
    }

    const toHex = String(topics[2] || "")
      .replace(/^0x/i, "")
      .toLowerCase()
      .slice(-40);

    if (toHex !== destinationHex) {
      continue;
    }

    const rawValue =
      decodeUint256(log.data);

    const amount =
      rawUSDTToNumber(rawValue);

    if (amount <= 0) continue;

    sender = decodeTopicAddress(topics[1]);

    confirmedAmount += amount;
  }

  if (confirmedAmount <= 0) {
    throw new Error(
      "Nenhuma transferência USDT TRC-20 confirmada para a carteira da tesouraria foi encontrada."
    );
  }

  if (confirmedAmount < expectedAmount) {
    throw new Error(
      `A blockchain confirmou ${confirmedAmount} USDT, abaixo dos ${expectedAmount} USDT informados.`
    );
  }

  return {
    tx_hash: txHash,
    amount_usdt: confirmedAmount,
    from: sender,
    to: companyAddress,
    contract: USDT_CONTRACT,
    network: TRON_NETWORK,
    block_number: receipt.blockNumber || null,
    confirmed: true
  };
}

/* =========================================================
   DEPÓSITO REAL DE USDT
========================================================= */

async function registerRealUSDTDeposit(req, res) {
  const body = req.body || {};

  const txHash = String(
    body.tx_hash ||
      body.txHash ||
      ""
  ).trim();

  const requestedAmount = Number(
    body.amount_usdt ??
      body.amount ??
      0
  );

  if (!txHash) {
    return json(res, 400, {
      ok: false,
      error: "TX Hash é obrigatório."
    });
  }

  if (
    !Number.isFinite(requestedAmount) ||
    requestedAmount <= 0
  ) {
    return json(res, 400, {
      ok: false,
      error: "Valor USDT inválido."
    });
  }

  const companyAddress = String(
    process.env.USDTMZ_TRON_WALLET_ADDRESS ||
      ""
  ).trim();

  if (!companyAddress) {
    return json(res, 500, {
      ok: false,
      error:
        "USDTMZ_TRON_WALLET_ADDRESS não configurado."
    });
  }

  if (!isValidTronAddress(companyAddress)) {
    return json(res, 500, {
      ok: false,
      error:
        "Endereço da tesouraria TRON inválido."
    });
  }

  const alreadyRegistered = await sql`
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
    WHERE blockchain_tx_hash = ${txHash}
    LIMIT 1
  `;

  if (alreadyRegistered.length) {
    return json(res, 409, {
      ok: false,
      error:
        "Esta TX Hash já está registrada na tesouraria.",
      transaction:
        alreadyRegistered[0]
    });
  }

  const verified =
    await verifyUSDTDeposit(
      txHash,
      companyAddress,
      requestedAmount
    );

  const transactionReference =
    `RESERVE_USDT:${txHash}`;

  const atomicResult =
    await sql.transaction(
      (txn) => [
        txn`
          WITH lock AS (
            SELECT pg_advisory_xact_lock(
              hashtext(${txHash})
            )
          ),

          wallet_update AS (
            UPDATE wallets
            SET
              balance =
                balance + ${verified.amount_usdt},
              status = 'ACTIVE',
              updated_at = NOW()
            WHERE
              wallet_address = ${companyAddress}
              AND network = ${TRON_NETWORK}
              AND asset = 'USDT'
              AND EXISTS (SELECT 1 FROM lock)
              AND NOT EXISTS (
                SELECT 1
                FROM transactions
                WHERE blockchain_tx_hash = ${txHash}
              )
            RETURNING
              id,
              wallet_address,
              network,
              asset,
              balance,
              status,
              updated_at
          ),

          transaction_insert AS (
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
            FROM wallet_update
            RETURNING
              id,
              type,
              asset,
              amount,
              status,
              reference,
              blockchain_tx_hash,
              created_at
          )

          SELECT
            (
              SELECT json_build_object(
                'id', id,
                'wallet_address', wallet_address,
                'network', network,
                'asset', asset,
                'balance', balance,
                'status', status,
                'updated_at', updated_at
              )
              FROM wallet_update
            ) AS wallet,

            (
              SELECT json_build_object(
                'id', id,
                'type', type,
                'asset', asset,
                'amount', amount,
                'status', status,
                'reference', reference,
                'blockchain_tx_hash',
                  blockchain_tx_hash,
                'created_at', created_at
              )
              FROM transaction_insert
            ) AS transaction,

            EXISTS (
              SELECT 1
              FROM transactions
              WHERE blockchain_tx_hash = ${txHash}
            ) AS tx_exists
        `
      ],
      {
        isolationMode: "Serializable"
      }
    );

  const result =
    atomicResult?.[0]?.[0] || {};

  if (
    result.tx_exists &&
    !result.transaction
  ) {
    return json(res, 409, {
      ok: false,
      error:
        "Esta TX já foi registrada por outra operação."
    });
  }

  if (
    !result.wallet ||
    !result.transaction
  ) {
    return json(res, 500, {
      ok: false,
      error:
        "A carteira USDT/TRON da tesouraria não existe no ledger. Nenhum saldo foi confirmado."
    });
  }

  const newBalance =
    normalizeNumber(result.wallet.balance);

  return json(res, 200, {
    ok: true,
    message:
      "Depósito USDT confirmado na blockchain e registrado na reserva real.",
    deposit: {
      tx_hash: verified.tx_hash,
      amount_usdt: verified.amount_usdt,
      from: verified.from,
      to: verified.to,
      contract: verified.contract,
      network: verified.network,
      block_number: verified.block_number,
      status: "COMPLETED"
    },
    reserve: {
      previous_balance:
        newBalance - verified.amount_usdt,
      added: verified.amount_usdt,
      new_balance: newBalance
    },
    transaction: result.transaction
  });
}

/* =========================================================
   DEPÓSITO MZN CONFIRMADO PELO ADMIN
========================================================= */

async function registerMZNDeposit(req, res) {
  const body = req.body || {};

  const amount = Number(
    body.amount_mzn ??
      body.amount ??
      0
  );

  const method = String(
    body.method ||
      body.payment_method ||
      ""
  )
    .trim()
    .toUpperCase();

  const reference = String(
    body.reference ||
      body.transaction_reference ||
      ""
  ).trim();

  if (
    !Number.isFinite(amount) ||
    amount <= 0
  ) {
    return json(res, 400, {
      ok: false,
      error: "Valor MZN inválido."
    });
  }

  if (!method) {
    return json(res, 400, {
      ok: false,
      error:
        "Método de abastecimento é obrigatório."
    });
  }

  if (!reference) {
    return json(res, 400, {
      ok: false,
      error:
        "Referência do abastecimento é obrigatória."
    });
  }

  const duplicate = await sql`
    SELECT id
    FROM transactions
    WHERE reference = ${reference}
    LIMIT 1
  `;

  if (duplicate.length) {
    return json(res, 409, {
      ok: false,
      error:
        "Esta referência já foi registrada."
    });
  }

  const result =
    await sql.transaction(
      (txn) => [
        txn`
          UPDATE wallets
          SET
            balance = balance + ${amount},
            status = 'ACTIVE',
            updated_at = NOW()
          WHERE
            asset IN (
              'MZN',
              'MZN_BALANCE',
              'MZN_RESERVE'
            )
            AND (
              network IS NULL
              OR UPPER(network) IN (
                'FIAT',
                'MZN',
                'MOZAMBIQUE'
              )
            )
            AND (
              status IS NULL
              OR UPPER(status) IN (
                'ACTIVE',
                'AVAILABLE'
              )
            )
          RETURNING
            id,
            balance
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
            'DEPOSIT_MZN',
            'MZN',
            ${amount},
            'COMPLETED',
            ${reference},
            NULL,
            NOW()
          WHERE EXISTS (
            SELECT 1
            FROM wallets
            WHERE
              asset IN (
                'MZN',
                'MZN_BALANCE',
                'MZN_RESERVE'
              )
          )
          RETURNING
            id,
            type,
            asset,
            amount,
            status,
            reference,
            created_at
        `
      ],
      {
        isolationMode: "Serializable"
      }
    );

  const wallet =
    result?.[0]?.[0];

  const transaction =
    result?.[1]?.[0];

  if (!wallet || !transaction) {
    return json(res, 500, {
      ok: false,
      error:
        "A carteira MZN da tesouraria não existe no ledger. Nenhum saldo foi criado."
    });
  }

  return json(res, 200, {
    ok: true,
    message:
      "Abastecimento MZN confirmado e registado.",
    deposit: {
      amount_mzn: amount,
      method,
      reference,
      status: "COMPLETED"
    },
    wallet
  });
}

/* =========================================================
   CONVERSÃO ADMIN MZN -> USDT
========================================================= */

async function convertMZNToUSDT(req, res) {
  const body = req.body || {};

  const amountMZN = Number(
    body.amount_mzn ??
      body.amount ??
      0
  );

  if (
    !Number.isFinite(amountMZN) ||
    amountMZN <= 0
  ) {
    return json(res, 400, {
      ok: false,
      error: "Valor MZN inválido."
    });
  }

  if (
    amountMZN < MIN_MZN ||
    amountMZN > MAX_MZN
  ) {
    return json(res, 400, {
      ok: false,
      error:
        `O valor deve estar entre ${MIN_MZN} e ${MAX_MZN} MZN.`
    });
  }

  if (!Number.isInteger(amountMZN)) {
    return json(res, 400, {
      ok: false,
      error:
        "O valor MZN deve ser inteiro."
    });
  }

  const usdtAmount =
    amountMZN / RATE;

  if (!Number.isFinite(usdtAmount) || usdtAmount <= 0) {
    return json(res, 400, {
      ok: false,
      error:
        "Valor USDT calculado inválido."
    });
  }

  const reference =
    String(
      body.reference ||
        `ADMIN-CONVERT-${Date.now()}`
    ).trim();

  const result =
    await sql.transaction(
      (txn) => [
        txn`
          SELECT pg_advisory_xact_lock(
            hashtext(${reference})
          )
        `,

        txn`
          WITH mzn_wallet AS (
            SELECT
              id,
              balance
            FROM wallets
            WHERE
              asset IN (
                'MZN',
                'MZN_BALANCE',
                'MZN_RESERVE'
              )
              AND (
                network IS NULL
                OR UPPER(network) IN (
                  'FIAT',
                  'MZN',
                  'MOZAMBIQUE'
                )
              )
              AND (
                status IS NULL
                OR UPPER(status) IN (
                  'ACTIVE',
                  'AVAILABLE'
                )
              )
            ORDER BY id
            LIMIT 1
            FOR UPDATE
          ),

          usdt_wallet AS (
            SELECT
              id,
              balance
            FROM wallets
            WHERE
              wallet_address =
                ${process.env.USDTMZ_TRON_WALLET_ADDRESS || ""}
              AND network =
                ${TRON_NETWORK}
              AND asset =
                'USDT'
              AND (
                status IS NULL
                OR UPPER(status) IN (
                  'ACTIVE',
                  'AVAILABLE'
                )
              )
            LIMIT 1
            FOR UPDATE
          )

          UPDATE wallets
          SET
            balance =
              balance - ${amountMZN},
            updated_at = NOW()
          WHERE
            id = (
              SELECT id
              FROM mzn_wallet
            )
            AND balance >= ${amountMZN}

          RETURNING
            id,
            balance
        `,

        txn`
          UPDATE wallets
          SET
            balance =
              balance - ${usdtAmount},
            updated_at = NOW()
          WHERE
            id = (
              SELECT id
              FROM wallets
              WHERE
                wallet_address =
                  ${process.env.USDTMZ_TRON_WALLET_ADDRESS || ""}
                AND network =
                  ${TRON_NETWORK}
                AND asset =
                  'USDT'
                AND (
                  status IS NULL
                  OR UPPER(status) IN (
                    'ACTIVE',
                    'AVAILABLE'
                  )
                )
              ORDER BY id
              LIMIT 1
              FOR UPDATE
            )
            AND balance >= ${usdtAmount}
          RETURNING
            id,
            balance
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
          VALUES (
            NULL,
            'CONVERSION',
            'MZN',
            ${amountMZN},
            'COMPLETED',
            ${reference},
            NULL,
            NOW()
          )
          RETURNING id
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
          VALUES (
            NULL,
            'CONVERSION',
            'USDT',
            ${usdtAmount},
            'COMPLETED',
            ${reference},
            NULL,
            NOW()
          )
          RETURNING id
        `
      ],
      {
        isolationMode: "Serializable"
      }
    );

  const mznUpdate =
    result?.[1]?.[0];

  const usdtUpdate =
    result?.[2]?.[0];

  if (!mznUpdate) {
    return json(res, 400, {
      ok: false,
      error:
        "Saldo MZN insuficiente ou carteira MZN inexistente."
    });
  }

  if (!usdtUpdate) {
    return json(res, 400, {
      ok: false,
      error:
        "USDT real insuficiente na tesouraria. Nenhuma conversão foi concluída."
    });
  }

  return json(res, 200, {
    ok: true,

    message:
      "Conversão administrativa concluída usando USDT real da tesouraria.",

    conversion: {
      mzn: amountMZN,
      rate: RATE,
      usdt: usdtAmount,
      reference,
      status: "COMPLETED"
    },

    reserve: {
      mzn_balance:
        normalizeNumber(
          mznUpdate.balance
        ),

      usdt_balance:
        normalizeNumber(
          usdtUpdate.balance
        )
    },

    binance_ready: true
  });
}

/* =========================================================
   DASHBOARD
========================================================= */

async function loadDashboard(req, res) {
  const wallets = await sql`
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
    const asset = classifyWallet(wallet);

    if (isMainCompanyWallet(wallet)) {
      if (asset === "USDT") {
        reserveUSDT +=
          normalizeNumber(wallet.balance);
      }

      if (asset === "TRX") {
        reserveTRX +=
          normalizeNumber(wallet.balance);
      }
    }

    if (
      asset === "MZN" &&
      (
        !wallet.status ||
        ["ACTIVE", "AVAILABLE"].includes(
          normalizeStatus(wallet.status)
        )
      )
    ) {
      reserveMZN +=
        normalizeNumber(wallet.balance);
    }
  }

  const transactions = await sql`
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
      .filter((tx) =>
        [
          "MZN",
          "MZN_RESERVE",
          "MZN_BALANCE",
          "USDT"
        ].includes(
          normalizeAsset(tx.asset)
        )
      )
      .map((tx) => ({
        id: tx.id,
        user_id: tx.user_id,
        type: tx.type,
        type_label:
          transactionTypeLabel(tx.type),
        asset:
          normalizeAsset(tx.asset),
        amount:
          normalizeNumber(tx.amount),
        status:
          normalizeStatus(tx.status),
        reference:
          tx.reference || null,
        blockchain_tx_hash:
          tx.blockchain_tx_hash || null,
        created_at: tx.created_at
      }));

  const withdrawals = await sql`
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
    withdrawals.map((item) => ({
      id: item.id,
      type: "WITHDRAWAL",
      source: "USER_WITHDRAWAL",
      withdrawal_id:
        item.withdrawal_id || null,
      user_id:
        item.user_id || null,
      amount:
        normalizeNumber(
          item.amount_requested ??
            item.amount_to_send ??
            item.amount
        ),
      amount_requested:
        normalizeNumber(item.amount_requested),
      withdrawal_fee:
        normalizeNumber(item.withdrawal_fee),
      amount_to_send:
        normalizeNumber(item.amount_to_send),
      asset:
        normalizeAsset(item.asset),
      network:
        item.network || null,
      destination_address:
        maskAddress(item.destination_address),
      destination_label:
        item.destination_address || "—",
      status:
        normalizeStatus(item.status),
      tx_hash:
        item.tx_hash || null,
      order_id:
        item.order_id || null,
      created_at:
        item.created_at || null,
      updated_at:
        item.updated_at || null,
      is_binance: false
    }));

  const orders = await sql`
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
    WHERE operation = 'BUY_USDT_ADMIN'
    ORDER BY
      created_at DESC NULLS LAST,
      id DESC
    LIMIT 500
  `;

  const binanceTransfers =
    orders.map((order) => ({
      id: `BINANCE-${order.id}`,
      type: "BINANCE_TRANSFER",
      source: "ADMIN_PURCHASE",
      order_id: order.order_id,
      name: order.name,
      phone: order.phone,
      amount:
        normalizeNumber(order.usdt_amount),
      amount_mzn:
        normalizeNumber(order.amount),
      usdt_amount:
        normalizeNumber(order.usdt_amount),
      rate:
        normalizeNumber(order.rate),
      asset: "USDT",
      network: TRON_NETWORK,
      destination_address:
        "BINANCE TRC-20",
      destination_label:
        "Binance / TRON TRC-20",
      status:
        normalizeStatus(order.status),
      tx_hash:
        order.blockchain_tx_hash || null,
      wallet_address:
        order.wallet_address || null,
      pagar_payment_id:
        order.pagar_payment_id || null,
      pagar_event_id:
        order.pagar_event_id || null,
      payment:
        order.payment || null,
      operation:
        order.operation,
      created_at:
        order.created_at || null,
      updated_at:
        order.updated_at || null,
      is_binance: true
    }));

  const reservedUSDT =
    binanceTransfers
      .filter((item) =>
        [
          "PROCESSING",
          "AUTHORIZED",
          "PAYMENT_CONFIRMED",
          "USDT_SENT"
        ].includes(item.status)
      )
      .reduce(
        (total, item) =>
          total +
          normalizeNumber(item.usdt_amount),
        0
      );

  const availableUSDT =
    Math.max(
      0,
      reserveUSDT - reservedUSDT
    );

  const history = [
    ...normalWithdrawals.map((item) => ({
      ...item,
      history_type: "WITHDRAWAL"
    })),

    ...binanceTransfers.map((item) => ({
      ...item,
      history_type: "BINANCE_TRANSFER"
    })),

    ...reserveTransactions.map((item) => ({
      ...item,
      history_type:
        "RESERVE_TRANSACTION"
    }))
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
    .slice(0, 1000);

  return json(res, 200, {
    ok: true,

    reserve: {
      currency_fiat: "MZN",
      currency_crypto: "USDT",

      mzn: {
        balance: reserveMZN,
        available: reserveMZN
      },

      usdt: {
        balance: reserveUSDT,
        reserved: reservedUSDT,
        available: availableUSDT,
        contract: USDT_CONTRACT,
        network: TRON_NETWORK
      },

      trx: {
        balance: reserveTRX,
        network: TRON_NETWORK
      },

      company_wallet: {
        configured:
          Boolean(
            process.env.USDTMZ_TRON_WALLET_ADDRESS
          ),

        address:
          process.env.USDTMZ_TRON_WALLET_ADDRESS
            ? maskAddress(
                process.env
                  .USDTMZ_TRON_WALLET_ADDRESS
              )
            : null,

        network: TRON_NETWORK
      }
    },

    wallets: wallets.map((wallet) => ({
      id: wallet.id,
      asset:
        normalizeAsset(wallet.asset),
      balance:
        normalizeNumber(wallet.balance),
      status:
        normalizeStatus(wallet.status),
      network:
        wallet.network || null,
      wallet_address:
        maskAddress(wallet.wallet_address),
      is_company_wallet:
        isMainCompanyWallet(wallet),
      created_at:
        wallet.created_at || null,
      updated_at:
        wallet.updated_at || null
    })),

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
      wallets: wallets.length,
      withdrawals:
        normalWithdrawals.length,
      binance_transfers:
        binanceTransfers.length,
      reserve_transactions:
        reserveTransactions.length
    },

    system: {
      reserve_control: true,
      real_usdt_required: true,
      fake_usdt_creation: false,
      blockchain_verification: true,
      solidified_receipt: true,
      duplicate_tx_protection: true,
      atomic_ledger: true,
      admin_only_treasury: true,

      usdt_contract:
        USDT_CONTRACT,

      network:
        TRON_NETWORK,

      rate: RATE,
      minimum_mzn: MIN_MZN,
      maximum_mzn: MAX_MZN
    }
  });
}

/* =========================================================
   HANDLER
========================================================= */

export default async function handler(req, res) {
  try {
    if (!verifyAdminSession(req)) {
      return json(res, 401, {
        ok: false,
        error: "Não autorizado."
      });
    }

    if (req.method === "GET") {
      return loadDashboard(req, res);
    }

    if (req.method === "POST") {
      const action = String(
        req.body?.action || ""
      )
        .trim()
        .toLowerCase();

      if (
        action ===
        "register_mzn_deposit"
      ) {
        return registerMZNDeposit(
          req,
          res
        );
      }

      if (
        action ===
        "convert_mzn_to_usdt"
      ) {
        return convertMZNToUSDT(
          req,
          res
        );
      }

      if (
        action ===
        "register_usdt_deposit" ||
        action ===
        "registerrealusdtdeposit"
      ) {
        return registerRealUSDTDeposit(
          req,
          res
        );
      }

      /*
       * Mantém compatibilidade com
       * o POST antigo da API 06.
       */
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
