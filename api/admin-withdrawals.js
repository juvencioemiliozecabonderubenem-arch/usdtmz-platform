import { neon } from "@neondatabase/serverless";
import { createHmac, timingSafeEqual, randomBytes } from "node:crypto";
import { TronWeb } from "tronweb";

const sql = neon(process.env.DATABASE_URL);

const COOKIE_NAME = "usdtmz_admin_session";

const RATE = 64;
const MIN_MZN = 64;
const MAX_MZN = 40000;

const USDT_CONTRACT =
  process.env.USDT_TRON_CONTRACT ||
  "TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t";

const USDT_DECIMALS = 6;

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

function safeCompare(a, b) {
  const A = Buffer.from(String(a));
  const B = Buffer.from(String(b));

  if (A.length !== B.length) return false;

  return timingSafeEqual(A, B);
}

function parseCookies(req) {
  const header = req.headers?.cookie || "";
  const cookies = {};

  for (const part of header.split(";")) {
    const index = part.indexOf("=");

    if (index === -1) continue;

    const key = part.slice(0, index).trim();
    const value = part.slice(index + 1).trim();

    cookies[key] = decodeURIComponent(value);
  }

  return cookies;
}

function verifyAdminSession(req) {
  const secret = process.env.ADMIN_SESSION_SECRET;

  if (!secret) return null;

  const cookies = parseCookies(req);
  const token = cookies[COOKIE_NAME];

  if (!token) return null;

  const parts = token.split(".");

  if (parts.length !== 2) return null;

  const [data, signature] = parts;

  try {
    const expected = createHmac("sha256", secret)
      .update(data)
      .digest("base64url");

    if (!safeCompare(signature, expected)) return null;

    const payload = JSON.parse(
      Buffer.from(data, "base64url").toString("utf8")
    );

    if (payload.id !== "admin") return null;

    if (!payload.email) return null;

    if (!payload.exp || Date.now() >= Number(payload.exp)) {
      return null;
    }

    return payload;
  } catch {
    return null;
  }
}

function requireAdmin(req, res) {
  const session = verifyAdminSession(req);

  if (!session) {
    res.status(401).json({
      success: false,
      message: "Sessão administrativa inválida ou expirada."
    });

    return null;
  }

  return session;
}

function makeReference(prefix = "TREASURY") {
  return `${prefix}-${Date.now()}-${randomBytes(5).toString("hex")}`;
}

function normalizeSource(source) {
  return String(source || "")
    .trim()
    .toUpperCase();
}

function isValidSource(source) {
  return SOURCES.includes(source);
}

function validTronAddress(address) {
  try {
    return TronWeb.isAddress(String(address || "").trim());
  } catch {
    return false;
  }
}

function getTreasuryAddress() {
  return String(
    process.env.USDTMZ_TRON_WALLET_ADDRESS || ""
  ).trim();
}

function getTronWeb() {
  const apiKey = process.env.TRON_PRO_API_KEY;

  const headers = apiKey
    ? { "TRON-PRO-API-KEY": apiKey }
    : {};

  return new TronWeb({
    fullHost: "https://api.trongrid.io",
    headers
  });
}

function topicToAddress(topic) {
  const clean = String(topic || "").replace(/^0x/, "");

  if (clean.length !== 64) return null;

  try {
    return TronWeb.address.fromHex("41" + clean.slice(-40));
  } catch {
    return null;
  }
}

function topicToAmount(data) {
  const clean = String(data || "").replace(/^0x/, "");

  if (!clean) return 0;

  try {
    return Number(BigInt("0x" + clean)) / 10 ** USDT_DECIMALS;
  } catch {
    return 0;
  }
}

async function getTransactionInfo(txHash) {
  const apiKey = process.env.TRON_PRO_API_KEY;

  if (!apiKey) {
    throw new Error("TRON_PRO_API_KEY não configurada.");
  }

  const response = await fetch(
    `https://api.trongrid.io/wallet/gettransactioninfobyid?value=${encodeURIComponent(
      txHash
    )}`,
    {
      headers: {
        "TRON-PRO-API-KEY": apiKey
      }
    }
  );

  if (!response.ok) {
    throw new Error("Falha ao consultar a blockchain TRON.");
  }

  return await response.json();
}

async function verifyUsdtTransfer(txHash, requestedAmount) {
  const treasuryAddress = getTreasuryAddress();

  if (!treasuryAddress) {
    return {
      confirmed: false,
      pending: false,
      reason: "Carteira Treasury não configurada."
    };
  }

  if (!validTronAddress(treasuryAddress)) {
    return {
      confirmed: false,
      pending: false,
      reason: "Endereço Treasury TRON inválido."
    };
  }

  const cleanHash = String(txHash || "").trim();

  if (!/^[a-fA-F0-9]{64}$/.test(cleanHash)) {
    return {
      confirmed: false,
      pending: false,
      reason: "TX hash TRON inválido."
    };
  }

  let info;

  try {
    info = await getTransactionInfo(cleanHash);
  } catch (error) {
    return {
      confirmed: false,
      pending: true,
      reason: error.message
    };
  }

  if (!info || !info.id) {
    return {
      confirmed: false,
      pending: true,
      reason: "Transação ainda não encontrada na TRON."
    };
  }

  const receipt = info.receipt || {};

  const result = String(receipt.result || "").toUpperCase();

  if (result && result !== "SUCCESS") {
    return {
      confirmed: false,
      pending: false,
      reason: "Transação TRON falhou."
    };
  }

  const contractResult =
    info.contractResult?.[0] ||
    info.contractResult ||
    null;

  if (contractResult) {
    const decoded = String(contractResult).toLowerCase();

    if (decoded !== "0000000000000000000000000000000000000000000000000000000000000001") {
      // Mantemos a verificação abaixo pelos eventos.
    }
  }

  let events = [];

  try {
    const apiKey = process.env.TRON_PRO_API_KEY;

    const response = await fetch(
      `https://api.trongrid.io/v1/transactions/${encodeURIComponent(
        cleanHash
      )}/events?only_confirmed=true&limit=200`,
      {
        headers: {
          "TRON-PRO-API-KEY": apiKey
        }
      }
    );

    if (response.ok) {
      const json = await response.json();
      events = Array.isArray(json?.data) ? json.data : [];
    }
  } catch {
    events = [];
  }

  const target = treasuryAddress;

  let received = 0;

  for (const event of events) {
    if (
      String(event?.event_name || "").toLowerCase() !== "transfer"
    ) {
      continue;
    }

    const contract = String(
      event?.contract_address ||
      event?.address ||
      ""
    );

    if (
      contract &&
      contract !== USDT_CONTRACT &&
      !contract.endsWith(USDT_CONTRACT.slice(-40))
    ) {
      continue;
    }

    let to = event?.result?.to || event?.result?.["0"] || null;
    let value = event?.result?.value || event?.result?.["2"] || null;

    if (!to && event?.topics?.length >= 3) {
      to = topicToAddress(event.topics[2]);
    }

    if (value == null && event?.data) {
      value = topicToAmount(event.data);
    }

    if (!to) continue;

    let normalizedTo = to;

    try {
      if (String(to).startsWith("41")) {
        normalizedTo = TronWeb.address.fromHex(String(to));
      }
    } catch {
      continue;
    }

    if (normalizedTo !== target) continue;

    let amount = Number(value || 0);

    if (!Number.isFinite(amount) || amount <= 0) {
      amount = topicToAmount(event.data);
    }

    received += amount;
  }

  if (received <= 0) {
    return {
      confirmed: false,
      pending: true,
      reason:
        "Transfer USDT para a carteira Treasury ainda não foi confirmado.",
      received: 0
    };
  }

  const expected = Number(requestedAmount);

  if (!Number.isFinite(expected) || expected <= 0) {
    return {
      confirmed: false,
      pending: false,
      reason: "Quantidade USDT inválida."
    };
  }

  if (received + 0.000001 < expected) {
    return {
      confirmed: false,
      pending: false,
      reason: `Valor recebido insuficiente. Recebido: ${received} USDT.`,
      received
    };
  }

  return {
    confirmed: true,
    pending: false,
    received,
    tx_hash: cleanHash
  };
}

async function getOrCreateWallet(asset) {
  const normalizedAsset = String(asset).toUpperCase();

  const existing = await sql`
    SELECT
      id,
      wallet_address,
      network,
      asset,
      balance,
      status,
      user_id
    FROM wallets
    WHERE asset = ${normalizedAsset}
    ORDER BY id ASC
    LIMIT 1
  `;

  if (existing.length) {
    return existing[0];
  }

  const address =
    normalizedAsset === "USDT"
      ? getTreasuryAddress()
      : null;

  const inserted = await sql`
    INSERT INTO wallets (
      wallet_address,
      network,
      asset,
      balance,
      status,
      created_at,
      updated_at
    )
    VALUES (
      ${address},
      ${normalizedAsset === "USDT" ? "TRON" : "MZN"},
      ${normalizedAsset},
      0,
      'ACTIVE',
      NOW(),
      NOW()
    )
    RETURNING *
  `;

  return inserted[0];
}

async function registerMZNDeposit(body) {
  const amount = Number(body.amount);
  const source = normalizeSource(body.source);
  const description = String(body.description || "").trim();

  if (!Number.isFinite(amount) || amount < MIN_MZN) {
    return {
      status: 400,
      body: {
        success: false,
        message: `Valor mínimo: ${MIN_MZN} MZN.`
      }
    };
  }

  if (amount > MAX_MZN) {
    return {
      status: 400,
      body: {
        success: false,
        message: `Valor máximo: ${MAX_MZN} MZN.`
      }
    };
  }

  if (!isValidSource(source)) {
    return {
      status: 400,
      body: {
        success: false,
        message: "Fonte de depósito inválida."
      }
    };
  }

  const reference =
    String(body.reference || "").trim() ||
    makeReference("MZN");

  const existing = await sql`
    SELECT id, reference, status, amount
    FROM transactions
    WHERE reference = ${reference}
    LIMIT 1
  `;

  if (existing.length) {
    return {
      status: 200,
      body: {
        success: true,
        status: existing[0].status,
        reference: existing[0].reference,
        amount: existing[0].amount,
        message:
          existing[0].status === "COMPLETED"
            ? "Depósito já confirmado."
            : "Depósito continua pendente."
      }
    };
  }

  await sql`
    INSERT INTO transactions (
      user_id,
      type,
      asset,
      amount,
      status,
      reference,
      created_at
    )
    VALUES (
      'ADMIN',
      'DEPOSIT_MZN',
      'MZN',
      ${amount},
      'PENDING',
      ${reference},
      NOW()
    )
  `;

  return {
    status: 200,
    body: {
      success: true,
      status: "PENDING",
      reference,
      amount,
      source,
      description,
      message:
        "Depósito registado como PENDING. O saldo só será atualizado após confirmação real."
    }
  };
}

async function confirmMZNDeposit(body) {
  const reference = String(body.reference || "").trim();

  if (!reference) {
    return {
      status: 400,
      body: {
        success: false,
        message: "reference é obrigatório."
      }
    };
  }

  const result = await sql`
    WITH pending AS (
      SELECT
        id,
        amount
      FROM transactions
      WHERE reference = ${reference}
        AND type = 'DEPOSIT_MZN'
        AND asset = 'MZN'
        AND status = 'PENDING'
      FOR UPDATE
    ),
    wallet_update AS (
      UPDATE wallets
      SET
        balance = balance + pending.amount,
        updated_at = NOW()
      FROM pending
      WHERE wallets.asset = 'MZN'
      RETURNING pending.id, pending.amount
    )
    UPDATE transactions
    SET
      status = 'COMPLETED'
    WHERE id IN (
      SELECT id FROM wallet_update
    )
    RETURNING
      id,
      amount,
      reference,
      status
  `;

  if (!result.length) {
    const existing = await sql`
      SELECT
        id,
        amount,
        reference,
        status
      FROM transactions
      WHERE reference = ${reference}
        AND type = 'DEPOSIT_MZN'
      LIMIT 1
    `;

    if (
      existing.length &&
      existing[0].status === "COMPLETED"
    ) {
      return {
        status: 200,
        body: {
          success: true,
          status: "COMPLETED",
          already_confirmed: true,
          transaction: existing[0]
        }
      };
    }

    return {
      status: 404,
      body: {
        success: false,
        message: "Depósito pendente não encontrado."
      }
    };
  }

  return {
    status: 200,
    body: {
      success: true,
      status: "COMPLETED",
      transaction: result[0],
      message: "Depósito MZN confirmado e saldo atualizado."
    }
  };
}

async function registerUSDTDeposit(body) {
  const amount = Number(body.amount);
  const txHash = String(
    body.tx_hash ||
    body.blockchain_tx_hash ||
    ""
  ).trim();

  const source = normalizeSource(
    body.source || "USDT_TRON"
  );

  if (!Number.isFinite(amount) || amount <= 0) {
    return {
      status: 400,
      body: {
        success: false,
        message: "Valor USDT inválido."
      }
    };
  }

  if (!/^[a-fA-F0-9]{64}$/.test(txHash)) {
    return {
      status: 400,
      body: {
        success: false,
        message: "TX hash TRON inválido."
      }
    };
  }

  if (source !== "USDT_TRON") {
    return {
      status: 400,
      body: {
        success: false,
        message: "Depósito USDT deve usar USDT_TRON."
      }
    };
  }

  const existing = await sql`
    SELECT
      id,
      reference,
      amount,
      status,
      blockchain_tx_hash
    FROM transactions
    WHERE blockchain_tx_hash = ${txHash}
    LIMIT 1
  `;

  if (existing.length) {
    if (existing[0].status === "COMPLETED") {
      return {
        status: 200,
        body: {
          success: true,
          status: "COMPLETED",
          already_confirmed: true,
          transaction: existing[0]
        }
      };
    }

    if (existing[0].status === "PENDING") {
      const verification = await verifyUsdtTransfer(
        txHash,
        existing[0].amount
      );

      if (verification.confirmed) {
        return await confirmUSDTDeposit({
          reference: existing[0].reference,
          tx_hash: txHash
        });
      }

      return {
        status: 200,
        body: {
          success: true,
          status: "PENDING",
          reference: existing[0].reference,
          message: verification.reason
        }
      };
    }

    return {
      status: 409,
      body: {
        success: false,
        message: "TX hash já existe no histórico."
      }
    };
  }

  const reference =
    String(body.reference || "").trim() ||
    makeReference("USDT");

  await sql`
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
      'ADMIN',
      'DEPOSIT_USDT',
      'USDT',
      ${amount},
      'PENDING',
      ${reference},
      ${txHash},
      NOW()
    )
  `;

  const verification = await verifyUsdtTransfer(
    txHash,
    amount
  );

  if (!verification.confirmed) {
    if (!verification.pending) {
      await sql`
        UPDATE transactions
        SET status = 'FAILED'
        WHERE reference = ${reference}
          AND status = 'PENDING'
      `;
    }

    return {
      status: 200,
      body: {
        success: true,
        status: verification.pending
          ? "PENDING"
          : "FAILED",
        reference,
        tx_hash: txHash,
        message: verification.reason
      }
    };
  }

  return await confirmUSDTDeposit({
    reference,
    tx_hash: txHash
  });
}

async function confirmUSDTDeposit(body) {
  const reference = String(body.reference || "").trim();
  const txHash = String(body.tx_hash || "").trim();

  if (!reference) {
    return {
      status: 400,
      body: {
        success: false,
        message: "reference é obrigatório."
      }
    };
  }

  const pending = await sql`
    SELECT
      id,
      amount,
      reference,
      status,
      blockchain_tx_hash
    FROM transactions
    WHERE reference = ${reference}
      AND type = 'DEPOSIT_USDT'
      AND asset = 'USDT'
    LIMIT 1
  `;

  if (!pending.length) {
    return {
      status: 404,
      body: {
        success: false,
        message: "Depósito USDT não encontrado."
      }
    };
  }

  const transaction = pending[0];

  if (transaction.status === "COMPLETED") {
    return {
      status: 200,
      body: {
        success: true,
        status: "COMPLETED",
        already_confirmed: true,
        transaction
      }
    };
  }

  const hash =
    txHash ||
    String(transaction.blockchain_tx_hash || "").trim();

  if (!hash) {
    return {
      status: 400,
      body: {
        success: false,
        message: "TX hash não encontrado."
      }
    };
  }

  const verification = await verifyUsdtTransfer(
    hash,
    transaction.amount
  );

  if (!verification.confirmed) {
    return {
      status: 200,
      body: {
        success: true,
        status: verification.pending
          ? "PENDING"
          : "FAILED",
        reference,
        tx_hash: hash,
        message: verification.reason
      }
    };
  }

  const result = await sql`
    WITH pending AS (
      SELECT
        id,
        amount
      FROM transactions
      WHERE reference = ${reference}
        AND type = 'DEPOSIT_USDT'
        AND asset = 'USDT'
        AND status = 'PENDING'
      FOR UPDATE
    ),
    wallet_update AS (
      UPDATE wallets
      SET
        balance = balance + pending.amount,
        updated_at = NOW()
      FROM pending
      WHERE wallets.asset = 'USDT'
      RETURNING pending.id, pending.amount
    )
    UPDATE transactions
    SET
      status = 'COMPLETED',
      blockchain_tx_hash = ${hash}
    WHERE id IN (
      SELECT id FROM wallet_update
    )
    RETURNING
      id,
      amount,
      reference,
      status,
      blockchain_tx_hash
  `;

  if (!result.length) {
    const existing = await sql`
      SELECT
        id,
        amount,
        reference,
        status,
        blockchain_tx_hash
      FROM transactions
      WHERE reference = ${reference}
      LIMIT 1
    `;

    if (
      existing.length &&
      existing[0].status === "COMPLETED"
    ) {
      return {
        status: 200,
        body: {
          success: true,
          status: "COMPLETED",
          already_confirmed: true,
          transaction: existing[0]
        }
      };
    }

    return {
      status: 409,
      body: {
        success: false,
        message:
          "Não foi possível confirmar o depósito de forma segura."
      }
    };
  }

  return {
    status: 200,
    body: {
      success: true,
      status: "COMPLETED",
      transaction: result[0],
      message:
        "Depósito USDT confirmado na TRON e saldo atualizado."
    }
  };
}

async function convertMZNToUSDT(body) {
  const amountMZN = Number(body.amount_mzn);

  if (
    !Number.isFinite(amountMZN) ||
    amountMZN < MIN_MZN ||
    amountMZN > MAX_MZN
  ) {
    return {
      status: 400,
      body: {
        success: false,
        message:
          `Valor deve estar entre ${MIN_MZN} e ${MAX_MZN} MZN.`
      }
    };
  }

  const usdtAmount = amountMZN / RATE;

  const reference =
    String(body.reference || "").trim() ||
    makeReference("LIQUIDITY");

  const result = await sql`
    WITH mzn_wallet AS (
      SELECT id, balance
      FROM wallets
      WHERE asset = 'MZN'
      FOR UPDATE
    ),
    usdt_wallet AS (
      SELECT id, balance
      FROM wallets
      WHERE asset = 'USDT'
      FOR UPDATE
    ),
    debit AS (
      UPDATE wallets
      SET
        balance = balance - ${amountMZN},
        updated_at = NOW()
      FROM mzn_wallet
      WHERE wallets.id = mzn_wallet.id
        AND mzn_wallet.balance >= ${amountMZN}
      RETURNING wallets.id
    ),
    reserve AS (
      UPDATE wallets
      SET
        balance = balance - ${usdtAmount},
        updated_at = NOW()
      FROM usdt_wallet
      WHERE wallets.id = usdt_wallet.id
        AND EXISTS (
          SELECT 1 FROM debit
        )
        AND usdt_wallet.balance >= ${usdtAmount}
      RETURNING wallets.id
    )
    SELECT *
    FROM reserve
  `;

  if (!result.length) {
    return {
      status: 400,
      body: {
        success: false,
        message:
          "Saldo MZN ou reserva real de USDT insuficiente."
      }
    };
  }

  await sql`
    INSERT INTO transactions (
      user_id,
      type,
      asset,
      amount,
      status,
      reference,
      created_at
    )
    VALUES (
      'ADMIN',
      'CONVERSION',
      'MZN',
      ${amountMZN},
      'COMPLETED',
      ${reference},
      NOW()
    )
  `;

  await sql`
    INSERT INTO transactions (
      user_id,
      type,
      asset,
      amount,
      status,
      reference,
      created_at
    )
    VALUES (
      'ADMIN',
      'RESERVE_IN',
      'USDT',
      ${usdtAmount},
      'RESERVED',
      ${reference},
      NOW()
    )
  `;

  return {
    status: 200,
    body: {
      success: true,
      status: "COMPLETED",
      reference,
      rate: RATE,
      mzn: amountMZN,
      usdt: usdtAmount,
      message:
        "Conversão concluída usando reserva real de USDT."
    }
  };
}

async function releaseReservation(body) {
  const reference = String(body.reference || "").trim();

  if (!reference) {
    return {
      status: 400,
      body: {
        success: false,
        message: "reference é obrigatório."
      }
    };
  }

  const rows = await sql`
    SELECT
      id,
      amount,
      status
    FROM transactions
    WHERE reference = ${reference}
      AND type = 'RESERVE_IN'
      AND asset = 'USDT'
      AND status = 'RESERVED'
    LIMIT 1
  `;

  if (!rows.length) {
    return {
      status: 404,
      body: {
        success: false,
        message: "Reserva USDT não encontrada."
      }
    };
  }

  const amount = Number(rows[0].amount);

  await sql`
    UPDATE wallets
    SET
      balance = balance + ${amount},
      updated_at = NOW()
    WHERE asset = 'USDT'
  `;

  await sql`
    UPDATE transactions
    SET status = 'COMPLETED'
    WHERE id = ${rows[0].id}
      AND status = 'RESERVED'
  `;

  return {
    status: 200,
    body: {
      success: true,
      status: "COMPLETED",
      reference,
      released_usdt: amount
    }
  };
}

async function getPendingDeposits() {
  const rows = await sql`
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
    WHERE status = 'PENDING'
      AND type IN (
        'DEPOSIT_MZN',
        'DEPOSIT_USDT'
      )
    ORDER BY created_at DESC
  `;

  return rows;
}

async function getLiquiditySources() {
  const pagarConfigured = Boolean(
    process.env.PAGAR_API_KEY &&
    process.env.PAGAR_WEBHOOK_SECRET
  );

  return [
    {
      code: "MPESA_BUSINESS",
      name: "M-Pesa",
      asset: "MZN",
      provider: "Pagar",
      configured: pagarConfigured,
      active: false
    },
    {
      code: "EMOLA_BUSINESS",
      name: "e-Mola",
      asset: "MZN",
      provider: "Pagar",
      configured: pagarConfigured,
      active: false
    },
    {
      code: "BANK",
      name: "Banco",
      asset: "MZN",
      configured: true,
      active: false
    },
    {
      code: "USDT_TRON",
      name: "USDT TRC20",
      asset: "USDT",
      network: "TRON",
      configured: Boolean(getTreasuryAddress()),
      active: true
    },
    {
      code: "EXTERNAL_WALLET",
      name: "Carteira externa",
      asset: "USDT",
      network: "TRON",
      configured: true,
      active: false
    },
    {
      code: "USDT_PURCHASE",
      name: "Compra de USDT",
      asset: "USDT",
      network: "TRON",
      configured: true,
      active: true
    },
    {
      code: "LIQUIDITY_PARTNER",
      name: "Parceiro de liquidez",
      asset: "USDT",
      configured: false,
      active: false
    },
    {
      code: "MANUAL_APPROVED",
      name: "Manual aprovado",
      asset: "MZN/USDT",
      configured: true,
      active: false
    }
  ];
}

async function getDashboard() {
  const mznWallet = await getOrCreateWallet("MZN");
  const usdtWallet = await getOrCreateWallet("USDT");

  const pendingDeposits = await getPendingDeposits();

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
      created_at,
      updated_at,
      pagar_payment_id,
      blockchain_tx_hash
    FROM orders
    ORDER BY created_at DESC
    LIMIT 50
  `;

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
      order_id
    FROM withdrawals
    ORDER BY created_at DESC
    LIMIT 50
  `;

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
    ORDER BY created_at DESC
    LIMIT 100
  `;

  const binanceTransfers = await sql`
    SELECT
      order_id,
      amount,
      usdt_amount,
      status,
      blockchain_tx_hash,
      created_at,
      updated_at
    FROM orders
    WHERE operation = 'BUY_USDT_ADMIN'
    ORDER BY created_at DESC
    LIMIT 50
  `;

  return {
    treasury: {
      mzn: Number(mznWallet?.balance || 0),
      usdt: Number(usdtWallet?.balance || 0),
      rate: RATE,
      min_mzn: MIN_MZN,
      max_mzn: MAX_MZN,
      wallet_address: getTreasuryAddress(),
      network: "TRON",
      asset: "USDT",
      contract: USDT_CONTRACT,
      decimals: USDT_DECIMALS
    },

    liquidity: {
      real_usdt_available: Number(usdtWallet?.balance || 0),
      mzn_available: Number(mznWallet?.balance || 0)
    },

    pending_deposits: pendingDeposits,

    orders,

    binance_transfers: binanceTransfers,

    withdrawals,

    transactions,

    sources: await getLiquiditySources(),

    system: {
      rate: RATE,
      min_mzn: MIN_MZN,
      max_mzn: MAX_MZN,
      network: "TRON",
      usdt_contract: USDT_CONTRACT,
      pagar_configured: Boolean(
        process.env.PAGAR_API_KEY &&
        process.env.PAGAR_WEBHOOK_SECRET
      ),
      tron_configured: Boolean(
        process.env.TRON_PRO_API_KEY &&
        getTreasuryAddress()
      )
    }
  };
}

async function registerFunding(body) {
  const type = String(body.type || "")
    .trim()
    .toUpperCase();

  if (type === "MZN") {
    return await registerMZNDeposit({
      ...body,
      source: normalizeSource(
        body.source || "MANUAL_APPROVED"
      )
    });
  }

  if (type === "USDT") {
    return await registerUSDTDeposit({
      ...body,
      source: "USDT_TRON"
    });
  }

  return {
    status: 400,
    body: {
      success: false,
      message: "type deve ser MZN ou USDT."
    }
  };
}

async function handleAction(req, res, action) {
  switch (action) {
    case "sources":
    case "liquidity_sources":
      return res.status(200).json({
        success: true,
        sources: await getLiquiditySources()
      });

    case "dashboard":
      return res.status(200).json({
        success: true,
        data: await getDashboard()
      });

    case "register_mzn_deposit":
      return sendResult(
        res,
        await registerMZNDeposit(req.body || {})
      );

    case "confirm_mzn_deposit":
      return sendResult(
        res,
        await confirmMZNDeposit(req.body || {})
      );

    case "register_usdt_deposit":
      return sendResult(
        res,
        await registerUSDTDeposit(req.body || {})
      );

    case "confirm_usdt_deposit":
      return sendResult(
        res,
        await confirmUSDTDeposit(req.body || {})
      );

    case "convert_mzn_to_usdt":
      return sendResult(
        res,
        await convertMZNToUSDT(req.body || {})
      );

    case "release_reservation":
      return sendResult(
        res,
        await releaseReservation(req.body || {})
      );

    case "register_funding":
      return sendResult(
        res,
        await registerFunding(req.body || {})
      );

    case "pending_deposits":
      return res.status(200).json({
        success: true,
        pending_deposits: await getPendingDeposits()
      });

    default:
      return res.status(400).json({
        success: false,
        message: "Ação inválida."
      });
  }
}

function sendResult(res, result) {
  return res.status(result.status).json(result.body);
}

export default async function handler(req, res) {
  try {
    const session = requireAdmin(req, res);

    if (!session) return;

    const url = new URL(
      req.url,
      `https://${req.headers.host || "localhost"}`
    );

    const action =
      String(
        url.searchParams.get("action") || "dashboard"
      )
        .trim()
        .toLowerCase();

    if (req.method === "GET") {
      if (
        action === "sources" ||
        action === "liquidity_sources" ||
        action === "dashboard" ||
        action === "pending_deposits"
      ) {
        return await handleAction(req, res, action);
      }

      return res.status(405).json({
        success: false,
        message: "Método não permitido."
      });
    }

    if (req.method !== "POST") {
      return res.status(405).json({
        success: false,
        message: "Método não permitido."
      });
    }

    return await handleAction(req, res, action);
  } catch (error) {
    console.error("admin-withdrawals error:", error);

    return res.status(500).json({
      success: false,
      message: "Erro interno do servidor."
    });
  }
    }
