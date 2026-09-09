import { neon } from "@neondatabase/serverless";
import { createHmac, createHash, timingSafeEqual } from "node:crypto";

const sql = neon(process.env.DATABASE_URL);

const COOKIE_NAME = "usdtmz_admin_session";
const USDT_CONTRACT = "TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t";
const TRON_NETWORK = "TRON";
const USDT_DECIMALS = 6;
const TRANSFER_TOPIC =
  "ddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef";

const RATE = 64;
const MIN_MZN = 64;
const MAX_MZN = 40000;

const SOURCES = [
  "MPESA_BUSINESS",
  "EMOLA_BUSINESS",
  "BANK",
  "USDT_TRON",
  "EXTERNAL_WALLET",
  "USDT_PURCHASE",
  "LIQUIDITY_PARTNER",
  "MANUAL_APPROVED"
];

function json(res, status, data) {
  return res.status(status).json(data);
}

function safeCompare(a, b) {
  const A = Buffer.from(String(a));
  const B = Buffer.from(String(b));
  if (A.length !== B.length) return false;
  return timingSafeEqual(A, B);
}

function getCookie(req, name) {
  const cookies = String(req.headers.cookie || "")
    .split(";")
    .map((x) => x.trim());

  const item = cookies.find((x) => x.startsWith(`${name}=`));
  return item ? item.slice(name.length + 1) : null;
}

function verifyAdminSession(req) {
  const secret = process.env.ADMIN_SESSION_SECRET;
  const token = getCookie(req, COOKIE_NAME);

  if (!secret || !token) return false;

  const parts = token.split(".");
  if (parts.length !== 2) return false;

  const [data, signature] = parts;

  const expected = createHmac("sha256", secret)
    .update(data)
    .digest("base64url");

  if (!safeCompare(signature, expected)) return false;

  try {
    const payload = JSON.parse(
      Buffer.from(data, "base64url").toString("utf8")
    );

    return Boolean(
      payload &&
      payload.id === "admin" &&
      payload.email &&
      Number(payload.exp) > Date.now()
    );
  } catch {
    return false;
  }
}

function num(v) {
  const n = Number(v);
  return Number.isFinite(n) ? n : 0;
}

function asset(v) {
  return String(v || "").trim().toUpperCase();
}

function status(v) {
  return String(v || "").trim().toUpperCase();
}

function mask(v) {
  if (!v) return "—";

  const s = String(v);

  return s.length <= 12
    ? s
    : `${s.slice(0, 6)}...${s.slice(-6)}`;
}

function validTx(v) {
  return /^[a-fA-F0-9]{64}$/.test(String(v || "").trim());
}

function validTron(v) {
  return /^T[1-9A-HJ-NP-Za-km-z]{33}$/.test(String(v || "").trim());
}

function companyAddress() {
  return String(
    process.env.USDTMZ_TRON_WALLET_ADDRESS || ""
  ).trim();
}

function tronBase() {
  return (
    process.env.TRON_API_BASE_URL ||
    "https://api.trongrid.io"
  ).replace(/\/+$/, "");
}

async function tronPost(path, body) {
  const key = process.env.TRON_PRO_API_KEY;

  if (!key) {
    throw new Error("TRON_PRO_API_KEY não configurado.");
  }

  const r = await fetch(`${tronBase()}${path}`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Accept: "application/json",
      "TRON-PRO-API-KEY": key
    },
    body: JSON.stringify(body)
  });

  const text = await r.text();

  let data;

  try {
    data = JSON.parse(text);
  } catch {
    throw new Error("Resposta inválida da TRON.");
  }

  if (!r.ok) {
    throw new Error(
      data?.Error ||
      data?.message ||
      `TRON HTTP ${r.status}`
    );
  }

  return data;
}

function doubleSha256(buffer) {
  return createHash("sha256")
    .update(
      createHash("sha256")
        .update(buffer)
        .digest()
    )
    .digest();
}

function base58Decode(value) {
  const alphabet =
    "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

  let n = 0n;

  for (const c of String(value)) {
    const i = alphabet.indexOf(c);

    if (i < 0) {
      throw new Error("Endereço TRON inválido.");
    }

    n = n * 58n + BigInt(i);
  }

  let hex = n.toString(16);

  if (hex.length % 2) {
    hex = `0${hex}`;
  }

  let bytes = Buffer.from(hex, "hex");

  let zeros = 0;

  for (const c of String(value)) {
    if (c === "1") {
      zeros++;
    } else {
      break;
    }
  }

  if (zeros) {
    bytes = Buffer.concat([
      Buffer.alloc(zeros),
      bytes
    ]);
  }

  return bytes;
}

function tronAddressToHex(address) {
  if (!validTron(address)) {
    throw new Error("Endereço TRON inválido.");
  }

  const decoded = base58Decode(address);

  if (decoded.length !== 25) {
    throw new Error("Endereço TRON inválido.");
  }

  const payload = decoded.subarray(0, 21);
  const checksum = decoded.subarray(21, 25);

  const expected = doubleSha256(payload)
    .subarray(0, 4);

  if (!timingSafeEqual(checksum, expected)) {
    throw new Error("Checksum do endereço TRON inválido.");
  }

  return payload
    .toString("hex")
    .toUpperCase();
}

function tronContractLogAddress(address) {
  return tronAddressToHex(address)
    .replace(/^41/, "")
    .toLowerCase();
}

function decodeTopicAddress(topic) {
  const v = String(topic || "")
    .replace(/^0x/i, "")
    .toLowerCase();

  if (!/^[0-9a-f]{64}$/.test(v)) {
    return null;
  }

  const payload = Buffer.from(
    `41${v.slice(-40)}`,
    "hex"
  );

  const checksum = doubleSha256(payload)
    .subarray(0, 4);

  const full = Buffer.concat([
    payload,
    checksum
  ]);

  const alphabet =
    "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

  let n = 0n;

  for (const byte of full) {
    n = n * 256n + BigInt(byte);
  }

  let out = "";

  while (n > 0n) {
    const r = Number(n % 58n);
    out = alphabet[r] + out;
    n /= 58n;
  }

  for (const byte of full) {
    if (byte === 0) {
      out = `1${out}`;
    } else {
      break;
    }
  }

  return out;
}

function decodeUint256(value) {
  const v = String(value || "")
    .replace(/^0x/i, "")
    .trim();

  if (!/^[0-9a-fA-F]+$/.test(v)) {
    throw new Error("Valor USDT inválido.");
  }

  return BigInt(`0x${v}`);
}

function rawUSDTToNumber(raw) {
  const base = 10n ** BigInt(USDT_DECIMALS);

  return (
    Number(raw / base) +
    Number(raw % base) / Number(base)
  );
}

async function verifyUSDTDeposit(
  txHash,
  destination,
  requestedAmount
) {
  if (!validTx(txHash)) {
    throw new Error("TX Hash TRON inválido.");
  }

  if (!validTron(destination)) {
    throw new Error(
      "Carteira da tesouraria inválida."
    );
  }

  const receipt = await tronPost(
    "/walletsolidity/gettransactioninfobyid",
    { value: txHash }
  );

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

  if (
    String(
      receipt.receipt?.result || ""
    ).toUpperCase() !== "SUCCESS"
  ) {
    throw new Error(
      "A execução da transação não foi concluída com sucesso."
    );
  }

  const contract =
    tronContractLogAddress(
      USDT_CONTRACT
    );

  const destinationHex =
    tronAddressToHex(destination)
      .replace(/^41/, "")
      .toLowerCase();

  let confirmed = 0;
  let sender = null;

  for (
    const log of Array.isArray(receipt.log)
      ? receipt.log
      : []
  ) {
    const logAddress =
      String(log.address || "")
        .replace(/^41/i, "")
        .toLowerCase();

    if (logAddress !== contract) {
      continue;
    }

    const topics =
      Array.isArray(log.topics)
        ? log.topics
        : [];

    if (topics.length < 3) {
      continue;
    }

    const topic0 =
      String(topics[0] || "")
        .replace(/^0x/i, "")
        .toLowerCase();

    if (topic0 !== TRANSFER_TOPIC) {
      continue;
    }

    const toHex =
      String(topics[2] || "")
        .replace(/^0x/i, "")
        .toLowerCase()
        .slice(-40);

    if (toHex !== destinationHex) {
      continue;
    }

    const amount = rawUSDTToNumber(
      decodeUint256(log.data)
    );

    if (amount <= 0) {
      continue;
    }

    sender = decodeTopicAddress(
      topics[1]
    );

    confirmed += amount;
  }

  if (confirmed <= 0) {
    throw new Error(
      "Nenhuma transferência USDT TRC-20 confirmada para a carteira da tesouraria foi encontrada."
    );
  }

  if (confirmed < Number(requestedAmount)) {
    throw new Error(
      `A blockchain confirmou ${confirmed} USDT, abaixo dos ${requestedAmount} USDT informados.`
    );
  }

  return {
    tx_hash: txHash,
    amount_usdt: confirmed,
    from: sender,
    to: destination,
    contract: USDT_CONTRACT,
    network: TRON_NETWORK,
    block_number:
      receipt.blockNumber || null,
    confirmed: true
  };
}

function walletWhereMZN() {
  return `
    asset IN ('MZN','MZN_BALANCE','MZN_RESERVE')
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
  `;
}

function walletWhereUSDT() {
  return `
    wallet_address = $1
    AND network = 'TRON'
    AND asset = 'USDT'
    AND (
      status IS NULL
      OR UPPER(status) IN (
        'ACTIVE',
        'AVAILABLE'
      )
    )
  `;
}

async function getTreasuryNumbers() {
  const address = companyAddress();

  const wallets = await sql`
    SELECT
      id,
      wallet_address,
      network,
      asset,
      balance,
      status,
      created_at,
      updated_at
    FROM wallets
    ORDER BY id ASC
  `;

  const mzn = wallets
    .filter((w) =>
      [
        "MZN",
        "MZN_BALANCE",
        "MZN_RESERVE"
      ].includes(asset(w.asset))
    )
    .reduce(
      (s, w) => s + num(w.balance),
      0
    );

  const usdt = wallets
    .filter(
      (w) =>
        asset(w.asset) === "USDT" &&
        String(w.network || "")
          .toUpperCase() === "TRON" &&
        (
          !address ||
          String(w.wallet_address || "") ===
            address
        )
    )
    .reduce(
      (s, w) => s + num(w.balance),
      0
    );

  const trx = wallets
    .filter(
      (w) =>
        asset(w.asset) === "TRX" &&
        String(w.network || "")
          .toUpperCase() === "TRON" &&
        (
          !address ||
          String(w.wallet_address || "") ===
            address
        )
    )
    .reduce(
      (s, w) => s + num(w.balance),
      0
    );

  const reservations = await sql`
    SELECT
      COALESCE(SUM(amount),0) AS total
    FROM transactions
    WHERE asset = 'USDT'
      AND type = 'RESERVE_IN'
      AND status = 'RESERVED'
      AND reference LIKE 'LIQUIDITY:%'
  `;

  const released = await sql`
    SELECT
      COALESCE(SUM(amount),0) AS total
    FROM transactions
    WHERE asset = 'USDT'
      AND type = 'RESERVE_OUT'
      AND status = 'COMPLETED'
      AND reference LIKE 'LIQUIDITY:%'
  `;

  const orders = await sql`
    SELECT
      COALESCE(SUM(usdt_amount),0) AS total
    FROM orders
    WHERE operation = 'BUY_USDT_ADMIN'
      AND status IN (
        'PAYMENT_CONFIRMED',
        'USDT_SENT'
      )
  `;

  const engineReserved =
    Math.max(
      0,
      num(reservations[0]?.total) -
        num(released[0]?.total)
    );

  const orderReserved =
    num(orders[0]?.total);

  const reserved =
    engineReserved + orderReserved;

  return {
    mzn,
    usdt,
    trx,
    reserved,
    available: Math.max(
      0,
      usdt - reserved
    ),
    engine_reserved:
      engineReserved,
    order_reserved:
      orderReserved
  };
}
/*
 * Registra MZN somente depois de uma confirmação administrativa.
 * As fontes de MZN são controladas exclusivamente pelo Admin.
 *
 * IMPORTANTE:
 * M-Pesa, e-Mola e banco fornecem MZN.
 * Eles não criam USDT.
 */
async function registerMZNDeposit(req, res) {
  const b = req.body || {};

  const amount = Number(
    b.amount_mzn ??
    b.amount ??
    0
  );

  const rawSource = String(
    b.source ??
    b.method ??
    ""
  )
    .trim()
    .toUpperCase();

  const SOURCE_ALIASES = {
    "M-PESA BUSINESS": "MPESA_BUSINESS",
    "M-PESA": "MPESA_BUSINESS",
    "MPESA": "MPESA_BUSINESS",

    "E-MOLA BUSINESS": "EMOLA_BUSINESS",
    "E-MOLA": "EMOLA_BUSINESS",
    "EMOLA": "EMOLA_BUSINESS",

    "TRANSFERÊNCIA BANCÁRIA": "BANK",
    "TRANSFERENCIA BANCARIA": "BANK",
    "DEPÓSITO BANCÁRIO": "BANK",
    "DEPOSITO BANCARIO": "BANK",

    "USDT — TRON / TRC-20": "USDT_TRON",
    "USDT - TRON / TRC-20": "USDT_TRON",

    "USDT — CARTEIRA EXTERNA": "EXTERNAL_WALLET",
    "USDT - CARTEIRA EXTERNA": "EXTERNAL_WALLET",

    "COMPRA DE USDT": "USDT_PURCHASE",
    "PARCEIRO DE LIQUIDEZ": "LIQUIDITY_PARTNER",
    "ENTRADA MANUAL APROVADA": "MANUAL_APPROVED"
  };

  const source =
    SOURCE_ALIASES[rawSource] ||
    rawSource;

  const reference = String(
    b.reference ??
    b.transaction_reference ??
    ""
  ).trim();

  if (
    !Number.isInteger(amount) ||
    amount <= 0
  ) {
    return json(res, 400, {
      ok: false,
      error: "Valor MZN inválido."
    });
  }

  if (!SOURCES.includes(source)) {
    return json(res, 400, {
      ok: false,
      error: "Fonte de abastecimento inválida.",
      allowed_sources: SOURCES
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
          SELECT pg_advisory_xact_lock(
            hashtext(${reference})
          )
        `,

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
            asset,
            balance,
            status
        `,

        txn`
          INSERT INTO transactions
            (
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
          )
          AND NOT EXISTS (
            SELECT 1
            FROM transactions
            WHERE reference = ${reference}
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
    result?.[1]?.[0];

  const transaction =
    result?.[2]?.[0];

  if (!wallet || !transaction) {
    return json(res, 500, {
      ok: false,
      error:
        "A carteira MZN da tesouraria não existe ou o abastecimento já foi processado. Nenhum saldo foi criado."
    });
  }

  return json(res, 200, {
    ok: true,

    message:
      "Abastecimento MZN confirmado e registado.",

    source,

    deposit: {
      amount_mzn: amount,
      reference,
      status: "COMPLETED"
    },

    wallet,

    transaction,

    liquidity_engine:
      "MZN_AVAILABLE"
  });
}


/*
 * Registra USDT somente depois de prova real on-chain.
 *
 * A blockchain é a fonte de verdade.
 * Nenhum USDT é criado pelo sistema.
 */
async function registerUSDTDeposit(req, res) {
  const b = req.body || {};

  const txHash = String(
    b.tx_hash ??
    b.txHash ??
    ""
  ).trim();

  const requested = Number(
    b.amount_usdt ??
    b.amount ??
    0
  );

  const source = String(
    b.source ??
    "USDT_TRON"
  )
    .trim()
    .toUpperCase();

  const reference = String(
    b.reference ??
    `USDT-TRON-${txHash}`
  ).trim();

  if (!validTx(txHash)) {
    return json(res, 400, {
      ok: false,
      error:
        "TX Hash TRON inválido."
    });
  }

  if (
    !Number.isFinite(requested) ||
    requested <= 0
  ) {
    return json(res, 400, {
      ok: false,
      error:
        "Valor USDT inválido."
    });
  }

  const treasury =
    companyAddress();

  if (!validTron(treasury)) {
    return json(res, 500, {
      ok: false,
      error:
        "USDTMZ_TRON_WALLET_ADDRESS não configurado ou inválido."
    });
  }

  const duplicate = await sql`
    SELECT id
    FROM transactions
    WHERE blockchain_tx_hash = ${txHash}
    LIMIT 1
  `;

  if (duplicate.length) {
    return json(res, 409, {
      ok: false,
      error:
        "Esta TX Hash já está registrada na tesouraria."
    });
  }

  const verified =
    await verifyUSDTDeposit(
      txHash,
      treasury,
      requested
    );

  const result =
    await sql.transaction(
      (txn) => [
        txn`
          SELECT pg_advisory_xact_lock(
            hashtext(${txHash})
          )
        `,

        txn`
          UPDATE wallets
          SET
            balance =
              balance + ${verified.amount_usdt},
            status = 'ACTIVE',
            updated_at = NOW()
          WHERE
            wallet_address = ${treasury}
            AND network = 'TRON'
            AND asset = 'USDT'
            AND (
              status IS NULL
              OR UPPER(status) IN (
                'ACTIVE',
                'AVAILABLE'
              )
            )
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
            status
        `,

        txn`
          INSERT INTO transactions
            (
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
            ${reference},
            ${txHash},
            NOW()
          WHERE EXISTS (
            SELECT 1
            FROM wallets
            WHERE
              wallet_address = ${treasury}
              AND network = 'TRON'
              AND asset = 'USDT'
          )
          AND NOT EXISTS (
            SELECT 1
            FROM transactions
            WHERE blockchain_tx_hash = ${txHash}
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
        `
      ],
      {
        isolationMode: "Serializable"
      }
    );

  const wallet =
    result?.[1]?.[0];

  const transaction =
    result?.[2]?.[0];

  if (!wallet || !transaction) {
    return json(res, 409, {
      ok: false,
      error:
        "A TX já foi processada ou a carteira USDT/TRON da tesouraria não existe."
    });
  }

  return json(res, 200, {
    ok: true,

    message:
      "USDT real confirmado na TRON e creditado na tesouraria.",

    source,

    deposit: verified,

    wallet,

    transaction,

    liquidity_engine:
      "USDT_REAL_AVAILABLE"
  });
}


/*
 * CONVERSÃO MZN → USDT
 *
 * Exemplo:
 *
 * 1000 MZN / 64 = 15.625 USDT
 *
 * O sistema:
 *
 * 1. verifica MZN real;
 * 2. verifica USDT real disponível;
 * 3. reserva USDT real;
 * 4. NÃO cria USDT;
 * 5. prepara a operação para o envio posterior.
 *
 * Se não houver USDT real suficiente,
 * nenhuma conversão é feita.
 */
async function convertMZNToUSDT(req, res) {
  const b = req.body || {};

  const amountMZN = Number(
    b.amount_mzn ??
    b.amount ??
    0
  );

  const orderId = String(
    b.order_id ??
    b.purchase_order_id ??
    ""
  ).trim();

  const reference = String(
    b.reference ??
    (
      orderId
        ? `LIQUIDITY:${orderId}`
        : `LIQUIDITY:${Date.now()}`
    )
  ).trim();

  if (
    !Number.isInteger(amountMZN) ||
    amountMZN < MIN_MZN ||
    amountMZN > MAX_MZN
  ) {
    return json(res, 400, {
      ok: false,
      error:
        `O valor deve estar entre ${MIN_MZN} e ${MAX_MZN} MZN e ser inteiro.`
    });
  }

  const usdtAmount =
    amountMZN / RATE;

  const before =
    await getTreasuryNumbers();

  if (before.mzn < amountMZN) {
    return json(res, 400, {
      ok: false,

      state:
        "INSUFFICIENT_MZN",

      error:
        "Saldo MZN insuficiente.",

      required_mzn:
        amountMZN,

      available_mzn:
        before.mzn
    });
  }

  if (
    before.available <
    usdtAmount
  ) {
    return json(res, 409, {
      ok: false,

      state:
        "LIQUIDITY_REQUIRED",

      message:
        "Liquidez USDT real insuficiente. Nenhuma conversão foi concluída.",

      required_usdt:
        usdtAmount,

      real_usdt:
        before.usdt,

      reserved_usdt:
        before.reserved,

      available_usdt:
        before.available,

      next_step:
        "Receber ou adquirir USDT real e confirmar a entrada na TRON."
    });
  }

  const result =
    await sql.transaction(
      (txn) => [
        txn`
          SELECT pg_advisory_xact_lock(
            hashtext(${reference})
          )
        `,

        txn`
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
          LIMIT 1
          FOR UPDATE
        `,

        txn`
          SELECT
            id,
            wallet_address,
            balance
          FROM wallets
          WHERE
            wallet_address = ${companyAddress()}
            AND network = 'TRON'
            AND asset = 'USDT'
          LIMIT 1
          FOR UPDATE
        `,

        txn`
          UPDATE wallets
          SET
            balance =
              balance - ${amountMZN},
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
            AND balance >= ${amountMZN}
          RETURNING
            id,
            balance
        `,

        txn`
          INSERT INTO transactions
            (
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
            'CONVERSION',
            'MZN',
            ${amountMZN},
            'COMPLETED',
            ${reference},
            NULL,
            NOW()
          WHERE NOT EXISTS (
            SELECT 1
            FROM transactions
            WHERE reference = ${reference}
              AND type = 'CONVERSION'
              AND asset = 'MZN'
          )
          RETURNING
            id,
            type,
            asset,
            amount,
            status,
            reference,
            created_at
        `,

        txn`
          INSERT INTO transactions
            (
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
            'RESERVE_IN',
            'USDT',
            ${usdtAmount},
            'RESERVED',
            ${reference},
            NULL,
            NOW()
          WHERE NOT EXISTS (
            SELECT 1
            FROM transactions
            WHERE reference = ${reference}
              AND type = 'RESERVE_IN'
              AND asset = 'USDT'
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

  const mznWallet =
    result?.[1]?.[0];

  const usdtWallet =
    result?.[2]?.[0];

  const mznUpdate =
    result?.[3]?.[0];

  const conversion =
    result?.[4]?.[0];

  const reservation =
    result?.[5]?.[0];

  if (
    !mznWallet ||
    !usdtWallet ||
    !mznUpdate ||
    !conversion ||
    !reservation
  ) {
    throw new Error(
      "A conversão não pôde ser concluída. A transação foi revertida."
    );
  }

  const after =
    await getTreasuryNumbers();

  return json(res, 200, {
    ok: true,

    state:
      "READY_FOR_BINANCE",

    message:
      "Conversão concluída com USDT real disponível na tesouraria. O USDT foi reservado; o envio blockchain continua na API 05.",

    conversion: {
      reference,

      order_id:
        orderId || null,

      amount_mzn:
        amountMZN,

      rate:
        RATE,

      amount_usdt:
        usdtAmount,

      source:
        "TREASURY_REAL_USDT",

      real_usdt_required:
        true,

      blockchain_created:
        false,

      ready_for_binance:
        true
    },

    reservation,

    treasury:
      after
  });
}
async function releaseReservation(req, res) {
  const b = req.body || {};

  const reference = String(
    b.reference ??
    ""
  ).trim();

  const amount = Number(
    b.amount_usdt ??
    b.amount ??
    0
  );

  if (!reference) {
    return json(res, 400, {
      ok: false,
      error:
        "A referência da reserva é obrigatória."
    });
  }

  if (
    !Number.isFinite(amount) ||
    amount <= 0
  ) {
    return json(res, 400, {
      ok: false,
      error:
        "Valor USDT para liberação inválido."
    });
  }

  const result =
    await sql.transaction(
      (txn) => [
        txn`
          SELECT pg_advisory_xact_lock(
            hashtext(${reference})
          )
        `,

        txn`
          SELECT
            COALESCE(SUM(amount), 0) AS reserved
          FROM transactions
          WHERE
            asset = 'USDT'
            AND type = 'RESERVE_IN'
            AND status = 'RESERVED'
            AND reference = ${reference}
        `,

        txn`
          SELECT
            COALESCE(SUM(amount), 0) AS released
          FROM transactions
          WHERE
            asset = 'USDT'
            AND type = 'RESERVE_OUT'
            AND status = 'COMPLETED'
            AND reference = ${reference}
        `,

        txn`
          INSERT INTO transactions
            (
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
            'RESERVE_OUT',
            'USDT',
            ${amount},
            'COMPLETED',
            ${reference},
            NULL,
            NOW()
          WHERE
            ${amount} <= (
              SELECT
                COALESCE(SUM(amount), 0)
              FROM transactions
              WHERE
                asset = 'USDT'
                AND type = 'RESERVE_IN'
                AND status = 'RESERVED'
                AND reference = ${reference}
            )
            -
            (
              SELECT
                COALESCE(SUM(amount), 0)
              FROM transactions
              WHERE
                asset = 'USDT'
                AND type = 'RESERVE_OUT'
                AND status = 'COMPLETED'
                AND reference = ${reference}
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

  const reserved =
    num(result?.[1]?.[0]?.reserved);

  const released =
    num(result?.[2]?.[0]?.released);

  const transaction =
    result?.[3]?.[0];

  const remaining =
    Math.max(
      0,
      reserved - released
    );

  if (!transaction) {
    return json(res, 409, {
      ok: false,

      error:
        "A quantidade solicitada excede a reserva disponível.",

      reference,

      reserved,

      already_released:
        released,

      remaining
    });
  }

  return json(res, 200, {
    ok: true,

    message:
      "Reserva USDT liberada.",

    transaction,

    remaining:
      Math.max(
        0,
        remaining - amount
      )
  });
}


async function getDashboard() {
  const treasury =
    await getTreasuryNumbers();

  const address =
    companyAddress();

  const [
    pendingOrders,
    confirmedOrders,
    binanceTransfers,
    withdrawals,
    recentTransactions
  ] = await Promise.all([
    sql`
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
        created_at,
        updated_at,
        mpesa_transaction_id,
        emola_transaction_id,
        pagar_payment_id,
        pagar_event_id,
        blockchain_tx_hash,
        wallet_address
      FROM orders
      WHERE operation = 'BUY_USDT_ADMIN'
        AND status = 'PENDING'
      ORDER BY created_at DESC
      LIMIT 100
    `,

    sql`
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
        created_at,
        updated_at,
        mpesa_transaction_id,
        emola_transaction_id,
        pagar_payment_id,
        pagar_event_id,
        blockchain_tx_hash,
        wallet_address
      FROM orders
      WHERE operation = 'BUY_USDT_ADMIN'
        AND status IN (
          'PAYMENT_CONFIRMED',
          'USDT_SENT',
          'COMPLETED',
          'FAILED',
          'CANCELLED'
        )
      ORDER BY created_at DESC
      LIMIT 100
    `,

    sql`
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
      WHERE
        asset = 'USDT'
        AND (
          type IN (
            'BINANCE_TRANSFER',
            'USDT_SENT',
            'WITHDRAWAL'
          )
          OR reference LIKE 'BINANCE:%'
        )
      ORDER BY created_at DESC
      LIMIT 100
    `,

    sql`
      SELECT
        id,
        user_id,
        amount,
        destination_address,
        network,
        status,
        tx_hash,
        created_at,
        updated_at
      FROM withdrawals
      ORDER BY created_at DESC
      LIMIT 100
    `,

    sql`
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
      ORDER BY created_at DESC
      LIMIT 100
    `
  ]);

  const normalWithdrawals =
    withdrawals.map((w) => ({
      ...w,
      amount: num(w.amount)
    }));

  const reserveUSDT =
    treasury.reserved;

  const availableUSDT =
    treasury.available;

  return {
    treasury: {
      mzn: treasury.mzn,
      usdt_real: treasury.usdt,
      trx_real: treasury.trx,

      reserved_usdt:
        reserveUSDT,

      available_usdt:
        availableUSDT,

      wallet_address:
        address || null,

      usdt_contract:
        USDT_CONTRACT,

      network:
        TRON_NETWORK,

      rate:
        RATE,

      min_mzn:
        MIN_MZN,

      max_mzn:
        MAX_MZN
    },

    liquidity: {
      status:
        availableUSDT > 0
          ? "COM_LIQUIDEZ"
          : "SEM_LIQUIDEZ",

      real_usdt:
        treasury.usdt,

      reserved_usdt:
        reserveUSDT,

      available_usdt:
        availableUSDT,

      engine_reserved_usdt:
        treasury.engine_reserved,

      order_reserved_usdt:
        treasury.order_reserved
    },

    orders: {
      pending:
        pendingOrders,

      confirmed:
        confirmedOrders
    },

    binance_transfers:
      binanceTransfers,

    withdrawals:
      normalWithdrawals,

    normal_withdrawals:
      normalWithdrawals,

    recent_transactions:
      recentTransactions,

    sources:
      SOURCES,

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

      admin_only_treasury:
        true
    }
  };
}


function transactionTypeLabel(type) {
  const labels = {
    DEPOSIT_MZN:
      "Depósito MZN",

    DEPOSIT_USDT:
      "Depósito USDT",

    CONVERSION:
      "Conversão",

    RESERVE_IN:
      "Reserva USDT",

    RESERVE_OUT:
      "Liberação de reserva",

    BINANCE_TRANSFER:
      "Envio para Binance",

    WITHDRAWAL:
      "Levantamento",

    USDT_SENT:
      "USDT enviado"
  };

  return (
    labels[type] ||
    type ||
    "Operação"
  );
}


function enrichTransaction(row) {
  return {
    ...row,

    amount:
      num(row.amount),

    type_label:
      transactionTypeLabel(
        row.type
      )
  };
}


function normalizeDashboard(data) {
  return {
    ...data,

    recent_transactions:
      Array.isArray(
        data.recent_transactions
      )
        ? data.recent_transactions.map(
            enrichTransaction
          )
        : [],

    binance_transfers:
      Array.isArray(
        data.binance_transfers
      )
        ? data.binance_transfers.map(
            enrichTransaction
          )
        : []
  };
}


/*
 * Lista as fontes disponíveis para
 * abastecimento da tesouraria.
 *
 * Elas aparecem no Admin.
 * A integração externa só deve ser
 * considerada concluída quando existir
 * uma confirmação real.
 */
async function getLiquiditySources(req, res) {
  const configured = {
    MPESA_BUSINESS:
      Boolean(
        process.env.MPESA_API_KEY ||
        process.env.PAGAR_API_KEY
      ),

    EMOLA_BUSINESS:
      Boolean(
        process.env.EMOLA_API_KEY ||
        process.env.PAGAR_API_KEY
      ),

    BANK:
      Boolean(
        process.env.BANK_API_URL
      ),

    USDT_TRON:
      Boolean(
        process.env.TRON_PRO_API_KEY
      ),

    EXTERNAL_WALLET:
      true,

    USDT_PURCHASE:
      Boolean(
        process.env.LIQUIDITY_PARTNER_API_URL
      ),

    LIQUIDITY_PARTNER:
      Boolean(
        process.env.LIQUIDITY_PARTNER_API_URL
      ),

    MANUAL_APPROVED:
      true
  };

  return json(res, 200, {
    ok: true,

    sources:
      SOURCES.map((name) => ({
        name,

        configured:
          Boolean(
            configured[name]
          ),

        active:
          false,

        real_funds_required:
          true,

        admin_only:
          true
      }))
  });
}export default async function handler(req, res) {
  try {
    if (!verifyAdminSession(req)) {
      return json(res, 401, {
        ok: false,
        authenticated: false,
        error:
          "Sessão de administrador inválida ou expirada."
      });
    }

    if (req.method === "GET") {
      const action = String(
        req.query?.action || ""
      )
        .trim()
        .toLowerCase();

      if (
        action === "liquidity_sources" ||
        action === "sources"
      ) {
        return getLiquiditySources(
          req,
          res
        );
      }

      const dashboard =
        await getDashboard();

      return json(
        res,
        200,
        normalizeDashboard(
          dashboard
        )
      );
    }

    if (req.method !== "POST") {
      return json(res, 405, {
        ok: false,
        error:
          "Método não permitido."
      });
    }

    const body =
      req.body || {};

    const action = String(
      body.action ??
      body.operation ??
      body.type ??
      ""
    )
      .trim()
      .toLowerCase();

    /*
     * ==================================================
     * REGISTAR ABASTECIMENTO MZN
     * ==================================================
     */
    if (
      action === "register_mzn_deposit" ||
      action === "register_mzn" ||
      action === "register_mzn_deposit_admin" ||
      action === "registermZndeposit".toLowerCase()
    ) {
      return registerMZNDeposit(
        req,
        res
      );
    }

    /*
     * ==================================================
     * REGISTAR USDT REAL
     * ==================================================
     */
    if (
      action === "register_usdt_deposit" ||
      action === "register_usdt" ||
      action === "registerrealusdtdeposit" ||
      action === "register_real_usdt_deposit"
    ) {
      return registerUSDTDeposit(
        req,
        res
      );
    }

    /*
     * ==================================================
     * CONVERTER MZN → USDT
     * ==================================================
     */
    if (
      action === "convert_mzn_to_usdt" ||
      action === "convert" ||
      action === "conversion"
    ) {
      return convertMZNToUSDT(
        req,
        res
      );
    }

    /*
     * ==================================================
     * LIBERAR RESERVA
     * ==================================================
     */
    if (
      action === "release_reservation" ||
      action === "release_reserve" ||
      action === "release_usdt_reservation"
    ) {
      return releaseReservation(
        req,
        res
      );
    }

    /*
     * ==================================================
     * CONSULTAR LIQUIDEZ
     * ==================================================
     */
    if (
      action === "liquidity" ||
      action === "get_liquidity" ||
      action === "check_liquidity"
    ) {
      const treasury =
        await getTreasuryNumbers();

      return json(res, 200, {
        ok: true,

        liquidity: {
          status:
            treasury.available > 0
              ? "COM_LIQUIDEZ"
              : "SEM_LIQUIDEZ",

          mzn:
            treasury.mzn,

          real_usdt:
            treasury.usdt,

          reserved_usdt:
            treasury.reserved,

          available_usdt:
            treasury.available,

          engine_reserved_usdt:
            treasury.engine_reserved,

          order_reserved_usdt:
            treasury.order_reserved
        }
      });
    }

    /*
     * ==================================================
     * ABASTECIMENTO MANUAL DE USDT
     *
     * Para USDT real, o Admin deve informar
     * TX Hash. A blockchain será verificada.
     * ==================================================
     */
    if (
      action === "register_funding" ||
      action === "register_abastecimento" ||
      action === "register_liquidity"
    ) {
      const fundingAsset =
        asset(
          body.asset ??
          body.currency ??
          "USDT"
        );

      if (fundingAsset === "MZN") {
        return registerMZNDeposit(
          req,
          res
        );
      }

      if (fundingAsset === "USDT") {
        return registerUSDTDeposit(
          req,
          res
        );
      }

      return json(res, 400, {
        ok: false,
        error:
          "Ativo de abastecimento inválido. Use MZN ou USDT."
      });
    }

    /*
     * ==================================================
     * ENVIAR PARA BINANCE
     *
     * A transferência blockchain é executada
     * pela API 05.
     *
     * Aqui apenas encaminhamos a operação.
     * ==================================================
     */
    if (
      action === "send_usdt_to_binance" ||
      action === "admin_binance_transfer"
    ) {
      const orderId = String(
        body.purchase_order_id ??
        body.order_id ??
        ""
      ).trim();

      if (!orderId) {
        return json(res, 400, {
          ok: false,
          error:
            "purchase_order_id é obrigatório."
        });
      }

      return json(res, 200, {
        ok: true,

        state:
          "READY_FOR_API_05",

        message:
          "A operação foi validada no Admin. O envio efetivo para Binance deve ser executado pela API 05.",

        purchase_order_id:
          orderId,

        binance_address:
          process.env
            .BINANCE_USDT_TRON_ADDRESS ||
          null,

        network:
          "TRON",

        asset:
          "USDT",

        api:
          "admin-withdrawal-process.js"
      });
    }

    /*
     * ==================================================
     * DASHBOARD MANUAL
     * ==================================================
     */
    if (
      action === "dashboard" ||
      action === "get_dashboard" ||
      action === ""
    ) {
      const dashboard =
        await getDashboard();

      return json(
        res,
        200,
        normalizeDashboard(
          dashboard
        )
      );
    }

    return json(res, 400, {
      ok: false,

      error:
        "Ação Admin desconhecida.",

      received_action:
        action,

      allowed_actions: [
        "register_mzn_deposit",
        "register_usdt_deposit",
        "convert_mzn_to_usdt",
        "release_reservation",
        "liquidity",
        "register_funding",
        "send_usdt_to_binance",
        "dashboard"
      ]
    });
  } catch (error) {
    console.error(
      "ADMIN-WITHDRAWALS ERROR:",
      error
    );

    return json(res, 500, {
      ok: false,

      error:
        error?.message ||
        "Erro interno da tesouraria.",

      system:
        "USDTMZ_ADMIN_TREASURY"
    });
  }
    }
