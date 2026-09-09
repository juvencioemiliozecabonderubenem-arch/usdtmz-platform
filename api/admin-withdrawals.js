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
