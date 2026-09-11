import { neon } from "@neondatabase/serverless";
import { createHmac, createHash, timingSafeEqual } from "node:crypto";

const sql = neon(process.env.DATABASE_URL);

const COOKIE = "usdtmz_admin_session";
const USDT_CONTRACT = "TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t";
const TRANSFER_TOPIC =
  "ddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef";

const RATE = 64;
const MIN_MZN = 64;
const MAX_MZN = 40000;

function out(res, status, data) {
  return res.status(status).json(data);
}

function safe(a, b) {
  const A = Buffer.from(String(a));
  const B = Buffer.from(String(b));
  return A.length === B.length && timingSafeEqual(A, B);
}

function cookie(req) {
  const s = String(req.headers.cookie || "");
  const x = s.split(";").map(v => v.trim())
    .find(v => v.startsWith(COOKIE + "="));
  return x ? x.slice(COOKIE.length + 1) : null;
}

function admin(req) {
  const token = cookie(req);
  const secret = process.env.ADMIN_SESSION_SECRET;
  if (!token || !secret) return false;

  const p = token.split(".");
  if (p.length !== 2) return false;

  const expected = createHmac("sha256", secret)
    .update(p[0])
    .digest("base64url");

  if (!safe(p[1], expected)) return false;

  try {
    const x = JSON.parse(
      Buffer.from(p[0], "base64url").toString()
    );
    return x.id === "admin" && Number(x.exp) > Date.now();
  } catch {
    return false;
  }
}

function n(v) {
  const x = Number(v);
  return Number.isFinite(x) ? x : 0;
}

function tx(v) {
  return /^[a-fA-F0-9]{64}$/.test(String(v || "").trim());
}

function tron(v) {
  return /^T[1-9A-HJ-NP-Za-km-z]{33}$/.test(String(v || "").trim());
}

function treasury() {
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
  if (!key) throw new Error("TRON_PRO_API_KEY não configurado.");

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
      data?.Error || data?.message || `TRON HTTP ${r.status}`
    );
  }

  return data;
}

/* =====================================================
   TRON
===================================================== */

function sha256(b) {
  return createHash("sha256").update(b).digest();
}

function doubleSha(b) {
  return sha256(sha256(b));
}

function base58Decode(value) {
  const alphabet =
    "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

  let x = 0n;

  for (const c of String(value)) {
    const i = alphabet.indexOf(c);
    if (i < 0) throw new Error("Endereço TRON inválido.");
    x = x * 58n + BigInt(i);
  }

  let h = x.toString(16);
  if (h.length % 2) h = "0" + h;

  let b = Buffer.from(h, "hex");

  let zeros = 0;
  for (const c of String(value)) {
    if (c === "1") zeros++;
    else break;
  }

  if (zeros) b = Buffer.concat([Buffer.alloc(zeros), b]);
  return b;
}

function tronHex(address) {
  if (!tron(address)) throw new Error("Endereço TRON inválido.");

  const d = base58Decode(address);

  if (d.length !== 25)
    throw new Error("Endereço TRON inválido.");

  const payload = d.subarray(0, 21);
  const checksum = d.subarray(21);

  if (!timingSafeEqual(checksum, doubleSha(payload).subarray(0, 4)))
    throw new Error("Checksum TRON inválido.");

  return payload.toString("hex").toLowerCase();
}

function topicAddress(topic) {
  const v = String(topic || "")
    .replace(/^0x/i, "")
    .toLowerCase();

  if (!/^[0-9a-f]{64}$/.test(v)) return null;

  const payload = Buffer.from("41" + v.slice(-40), "hex");
  const full = Buffer.concat([
    payload,
    doubleSha(payload).subarray(0, 4)
  ]);

  const alphabet =
    "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

  let x = 0n;

  for (const b of full)
    x = x * 256n + BigInt(b);

  let result = "";

  while (x > 0n) {
    result =
      alphabet[Number(x % 58n)] + result;
    x /= 58n;
  }

  for (const b of full) {
    if (b === 0) result = "1" + result;
    else break;
  }

  return result;
}

function uint256(v) {
  const x = String(v || "")
    .replace(/^0x/i, "");

  if (!/^[0-9a-fA-F]+$/.test(x))
    throw new Error("Valor USDT inválido.");

  return BigInt("0x" + x);
}

function usdtNumber(raw) {
  const base = 1000000n;
  return Number(raw / base) +
    Number(raw % base) / 1000000;
}

/* =====================================================
   VERIFICAÇÃO REAL USDT
===================================================== */

async function verifyUSDT(txHash) {
  const wallet = treasury();

  if (!tron(wallet))
    throw new Error("Carteira TRON da tesouraria inválida.");

  if (!tx(txHash))
    throw new Error("TX Hash TRON inválido.");

  const receipt = await tronPost(
    "/walletsolidity/gettransactioninfobyid",
    { value: txHash }
  );

  if (
    String(receipt?.id || "").toLowerCase() !==
    txHash.toLowerCase()
  ) {
    throw new Error(
      "A transação ainda não possui receipt solidificado."
    );
  }

  if (
    String(receipt?.receipt?.result || "")
      .toUpperCase() !== "SUCCESS"
  ) {
    throw new Error(
      "A transação TRON não foi concluída com sucesso."
    );
  }

  const contract =
    tronHex(USDT_CONTRACT).replace(/^41/, "");

  const destination =
    tronHex(wallet).replace(/^41/, "");

  let amount = 0;
  let from = null;

  for (const log of Array.isArray(receipt.log)
    ? receipt.log
    : []) {

    const address =
      String(log.address || "")
        .replace(/^41/i, "")
        .toLowerCase();

    if (address !== contract) continue;

    const topics = Array.isArray(log.topics)
      ? log.topics
      : [];

    if (topics.length < 3) continue;

    const topic0 =
      String(topics[0] || "")
        .replace(/^0x/i, "")
        .toLowerCase();

    if (topic0 !== TRANSFER_TOPIC) continue;

    const to =
      String(topics[2] || "")
        .replace(/^0x/i, "")
        .toLowerCase()
        .slice(-40);

    if (to !== destination) continue;

    const value = usdtNumber(uint256(log.data));

    if (value > 0) {
      amount += value;
      from = topicAddress(topics[1]);
    }
  }

  if (amount <= 0)
    throw new Error(
      "Nenhuma transferência USDT para a tesouraria foi encontrada."
    );

  return {
    tx_hash: txHash,
    amount_usdt: amount,
    from,
    to: wallet,
    network: "TRON",
    contract: USDT_CONTRACT,
    block_number: receipt.blockNumber || null
  };
}

/* =====================================================
   SALDOS
===================================================== */

async function balances() {
  const address = treasury();

  const rows = await sql`
    SELECT asset, network, wallet_address, balance
    FROM wallets
  `;

  const mzn = rows
    .filter(x =>
      ["MZN","MZN_BALANCE","MZN_RESERVE"]
        .includes(String(x.asset).toUpperCase())
    )
    .reduce((a,x) => a+n(x.balance),0);

  const usdt = rows
    .filter(x =>
      String(x.asset).toUpperCase() === "USDT" &&
      String(x.network).toUpperCase() === "TRON" &&
      String(x.wallet_address) === address
    )
    .reduce((a,x) => a+n(x.balance),0);

  const trx = rows
    .filter(x =>
      String(x.asset).toUpperCase() === "TRX" &&
      String(x.network).toUpperCase() === "TRON" &&
      String(x.wallet_address) === address
    )
    .reduce((a,x) => a+n(x.balance),0);

  const r = await sql`
    SELECT COALESCE(SUM(amount),0) total
    FROM transactions
    WHERE asset='USDT'
      AND type='RESERVE_IN'
      AND status='RESERVED'
  `;

  const o = await sql`
    SELECT COALESCE(SUM(usdt_amount),0) total
    FROM orders
    WHERE operation='BUY_USDT_ADMIN'
      AND status IN ('PAYMENT_CONFIRMED','USDT_SENT')
  `;

  const reserved =
    n(r[0]?.total) + n(o[0]?.total);

  return {
    mzn,
    usdt,
    trx,
    reserved,
    available: Math.max(0, usdt - reserved)
  };
}

/* =====================================================
   DEPÓSITO MZN — FICA PENDENTE
===================================================== */

async function depositMZN(req,res) {
  const b = req.body || {};

  const amount = Number(
    b.amount_mzn ?? b.amount ?? 0
  );

  const reference = String(
    b.reference ?? ""
  ).trim();

  const source = String(
    b.source ?? b.method ?? "MANUAL_APPROVED"
  ).trim().toUpperCase();

  if (!Number.isInteger(amount) || amount <= 0)
    return out(res,400,{ok:false,error:"Valor MZN inválido."});

  if (!reference)
    return out(res,400,{
      ok:false,
      error:"Referência obrigatória."
    });

  const exists = await sql`
    SELECT id,status
    FROM transactions
    WHERE reference=${reference}
    LIMIT 1
  `;

  if (exists.length)
    return out(res,409,{
      ok:false,
      error:"Esta referência já existe.",
      status:exists[0].status
    });

  const rows = await sql`
    INSERT INTO transactions
      (user_id,type,asset,amount,status,reference,created_at)
    VALUES
      (NULL,'DEPOSIT_MZN','MZN',${amount},
       'PENDING',${reference},NOW())
    RETURNING id,type,asset,amount,status,reference,created_at
  `;

  return out(res,200,{
    ok:true,
    message:"Depósito MZN criado e colocado como PENDENTE.",
    source,
    deposit:rows[0]
  });
}

/* =====================================================
   CONFIRMAR DEPÓSITO MZN
===================================================== */

async function confirmMZN(req,res) {
  const reference = String(
    req.body?.reference || ""
  ).trim();

  if (!reference)
    return out(res,400,{
      ok:false,
      error:"Referência obrigatória."
    });

  const result = await sql.transaction(txn => [
    txn`
      SELECT pg_advisory_xact_lock(
        hashtext(${reference})
      )
    `,

    txn`
      SELECT *
      FROM transactions
      WHERE reference=${reference}
        AND type='DEPOSIT_MZN'
        AND asset='MZN'
        AND status='PENDING'
      LIMIT 1
      FOR UPDATE
    `,

    txn`
      UPDATE wallets
      SET balance=balance+(
        SELECT amount
        FROM transactions
        WHERE reference=${reference}
          AND type='DEPOSIT_MZN'
          AND status='PENDING'
        LIMIT 1
      ),
      status='ACTIVE',
      updated_at=NOW()
      WHERE asset IN ('MZN','MZN_BALANCE','MZN_RESERVE')
      RETURNING id,asset,balance
    `,

    txn`
      UPDATE transactions
      SET status='COMPLETED'
      WHERE reference=${reference}
        AND type='DEPOSIT_MZN'
        AND status='PENDING'
      RETURNING *
    `
  ],{isolationMode:"Serializable"});

  const deposit=result?.[1]?.[0];
  const wallet=result?.[2]?.[0];
  const transaction=result?.[3]?.[0];

  if(!deposit || !wallet || !transaction)
    return out(res,409,{
      ok:false,
      error:"Depósito não encontrado ou já confirmado."
    });

  return out(res,200,{
    ok:true,
    message:"Depósito MZN confirmado.",
    wallet,
    transaction
  });
}

/* =====================================================
   DEPÓSITO USDT — PENDENTE
===================================================== */

async function depositUSDT(req,res) {
  const b=req.body||{};
  const hash=String(
    b.tx_hash ?? b.txHash ?? ""
  ).trim();

  const reference=String(
    b.reference || `USDT-${hash}`
  ).trim();

  if(!tx(hash))
    return out(res,400,{
      ok:false,
      error:"TX Hash inválido."
    });

  const exists=await sql`
    SELECT id,status
    FROM transactions
    WHERE blockchain_tx_hash=${hash}
       OR reference=${reference}
    LIMIT 1
  `;

  if(exists.length)
    return out(res,409,{
      ok:false,
      error:"Esta transação já está registrada.",
      status:exists[0].status
    });

  const row=await sql`
    INSERT INTO transactions
      (user_id,type,asset,amount,status,reference,
       blockchain_tx_hash,created_at)
    VALUES
      (NULL,'DEPOSIT_USDT','USDT',0,'PENDING',
       ${reference},${hash},NOW())
    RETURNING *
  `;

  return out(res,200,{
    ok:true,
    message:"Depósito USDT criado como PENDENTE.",
    deposit:row[0],
    wallet_address:treasury(),
    network:"TRON",
    asset:"USDT"
  });
}

/* =====================================================
   CONFIRMAR USDT — BLOCKCHAIN
===================================================== */

async function confirmUSDT(req,res) {
  const hash=String(
    req.body?.tx_hash ??
    req.body?.txHash ??
    ""
  ).trim();

  if(!tx(hash))
    return out(res,400,{
      ok:false,
      error:"TX Hash inválido."
    });

  const verified=await verifyUSDT(hash);

  const result=await sql.transaction(txn=>[
    txn`
      SELECT pg_advisory_xact_lock(
        hashtext(${hash})
      )
    `,

    txn`
      SELECT *
      FROM transactions
      WHERE blockchain_tx_hash=${hash}
        AND type='DEPOSIT_USDT'
        AND status='PENDING'
      LIMIT 1
      FOR UPDATE
    `,

    txn`
      UPDATE wallets
      SET balance=balance+${verified.amount_usdt},
          status='ACTIVE',
          updated_at=NOW()
      WHERE wallet_address=${treasury()}
        AND network='TRON'
        AND asset='USDT'
      RETURNING id,wallet_address,network,asset,balance
    `,

    txn`
      UPDATE transactions
      SET amount=${verified.amount_usdt},
          status='COMPLETED'
      WHERE blockchain_tx_hash=${hash}
        AND type='DEPOSIT_USDT'
        AND status='PENDING'
      RETURNING *
    `
  ],{isolationMode:"Serializable"});

  const deposit=result?.[1]?.[0];
  const wallet=result?.[2]?.[0];
  const transaction=result?.[3]?.[0];

  if(!deposit || !wallet || !transaction)
    return out(res,409,{
      ok:false,
      error:
        "Depósito não encontrado, já confirmado ou carteira USDT inexistente."
    });

  return out(res,200,{
    ok:true,
    message:"USDT confirmado na blockchain e creditado.",
    deposit:verified,
    wallet,
    transaction
  });
}

/* =====================================================
   CONVERSÃO
===================================================== */

async function convert(req,res) {
  const amount=Number(
    req.body?.amount_mzn ??
    req.body?.amount ??
    0
  );

  const reference=String(
    req.body?.reference ||
    `LIQUIDITY:${Date.now()}`
  ).trim();

  if(
    !Number.isInteger(amount) ||
    amount<MIN_MZN ||
    amount>MAX_MZN
  )
    return out(res,400,{
      ok:false,
      error:`Valor entre ${MIN_MZN} e ${MAX_MZN} MZN.`
    });

  const usdtAmount=amount/RATE;
  const before=await balances();

  if(before.mzn<amount)
    return out(res,400,{
      ok:false,
      error:"Saldo MZN insuficiente."
    });

  if(before.available<usdtAmount)
    return out(res,409,{
      ok:false,
      error:"USDT real disponível insuficiente.",
      required_usdt:usdtAmount,
      available_usdt:before.available
    });

  const result=await sql.transaction(txn=>[
    txn`
      SELECT pg_advisory_xact_lock(
        hashtext(${reference})
      )
    `,

    txn`
      UPDATE wallets
      SET balance=balance-${amount},
          updated_at=NOW()
      WHERE asset IN ('MZN','MZN_BALANCE','MZN_RESERVE')
        AND balance>=${amount}
      RETURNING id,balance
    `,

    txn`
      INSERT INTO transactions
        (user_id,type,asset,amount,status,reference,created_at)
      VALUES
        (NULL,'CONVERSION','MZN',${amount},
         'COMPLETED',${reference},NOW())
      RETURNING *
    `,

    txn`
      INSERT INTO transactions
        (user_id,type,asset,amount,status,reference,created_at)
      VALUES
        (NULL,'RESERVE_IN','USDT',${usdtAmount},
         'RESERVED',${reference},NOW())
      RETURNING *
    `
  ],{isolationMode:"Serializable"});

  if(!result?.[1]?.[0])
    return out(res,409,{
      ok:false,
      error:"Saldo MZN insuficiente."
    });

  return out(res,200,{
    ok:true,
    message:"MZN convertido e USDT real reservado.",
    conversion:{
      reference,
      amount_mzn:amount,
      rate:RATE,
      amount_usdt:usdtAmount
    }
  });
}

/* =====================================================
   DASHBOARD
===================================================== */

async function dashboard() {
  const t=await balances();

  const [
    pending,
    orders,
    transactions
  ]=await Promise.all([

    sql`
      SELECT *
      FROM transactions
      WHERE status='PENDING'
      ORDER BY created_at DESC
      LIMIT 100
    `,

    sql`
      SELECT *
      FROM orders
      WHERE operation='BUY_USDT_ADMIN'
      ORDER BY created_at DESC
      LIMIT 100
    `,

    sql`
      SELECT *
      FROM transactions
      ORDER BY created_at DESC
      LIMIT 100
    `
  ]);

  return {
    treasury:{
      mzn:t.mzn,
      usdt_real:t.usdt,
      trx_real:t.trx,
      reserved_usdt:t.reserved,
      available_usdt:t.available,
      wallet_address:treasury(),
      usdt_contract:USDT_CONTRACT,
      network:"TRON",
      rate:RATE,
      min_mzn:MIN_MZN,
      max_mzn:MAX_MZN
    },

    liquidity:{
      status:t.available>0
        ? "COM_LIQUIDEZ"
        : "SEM_LIQUIDEZ",
      real_usdt:t.usdt,
      reserved_usdt:t.reserved,
      available_usdt:t.available
    },

    deposits:{
      pending
    },

    orders,
    recent_transactions:transactions,

    system:{
      admin_only_treasury:true,
      real_usdt_required:true,
      blockchain_verification:true,
      pending_deposits:true,
      duplicate_protection:true
    }
  };
}

/* =====================================================
   HANDLER
===================================================== */

export default async function handler(req,res){

  try{

    if(!admin(req))
      return out(res,401,{
        ok:false,
        error:"Sessão Admin inválida ou expirada."
      });

    if(req.method==="GET")
      return out(res,200,await dashboard());

    if(req.method!=="POST")
      return out(res,405,{
        ok:false,
        error:"Método não permitido."
      });

    const action=String(
      req.body?.action ||
      req.body?.operation ||
      ""
    ).trim().toLowerCase();

    if([
      "register_mzn_deposit",
      "register_mzn",
      "register_mzn_deposit_admin"
    ].includes(action))
      return depositMZN(req,res);

    if([
      "confirm_mzn_deposit",
      "confirm_mzn"
    ].includes(action))
      return confirmMZN(req,res);

    if([
      "register_usdt_deposit",
      "register_usdt",
      "register_real_usdt_deposit"
    ].includes(action))
      return depositUSDT(req,res);

    if([
      "confirm_usdt_deposit",
      "confirm_usdt"
    ].includes(action))
      return confirmUSDT(req,res);

    if([
      "convert_mzn_to_usdt",
      "convert",
      "conversion"
    ].includes(action))
      return convert(req,res);

    if([
      "liquidity",
      "get_liquidity",
      "check_liquidity"
    ].includes(action))
      return out(res,200,{
        ok:true,
        liquidity:await balances()
      });

    if(
      action==="dashboard" ||
      action==="get_dashboard" ||
      action===""
    )
      return out(res,200,await dashboard());

    return out(res,400,{
      ok:false,
      error:"Ação Admin desconhecida.",
      received_action:action
    });

  }catch(error){

    console.error(
      "ADMIN-WITHDRAWALS ERROR:",
      error
    );

    return out(res,500,{
      ok:false,
      error:error?.message ||
        "Erro interno da tesouraria."
    });
  }
}
