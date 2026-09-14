// api/admin-withdrawals.js
// USDTMZ — API06 CENTRAL ADMIN / TESOURARIA
// Mantém todas as ações do API06. Não cria API13.

import{createHmac,timingSafeEqual,randomBytes}from"node:crypto";
import{neon}from"@neondatabase/serverless";
import{TronWeb}from"tronweb";

const sql=neon(process.env.DATABASE_URL);
const COOKIE="usdtmz_admin_session",MIN=64,MAX=40000,DEC=6;
const CONTRACT=process.env.USDT_TRON_CONTRACT||
 "TR7NHqjeKQXGTCi8q8ZY4pL8otSzgjLj6t";
const TRON=process.env.TRON_HOST||"https://api.trongrid.io";
const PAY=process.env.PAY_API_BASE_URL||
 "https://pay.co.mz/api/public/v1";
const SOURCES=[
 "MPESA_BUSINESS","MKESH_BUSINESS","EMOLA_BUSINESS","BANK",
 "USDT_TRON","EXTERNAL_WALLET","USDT_PURCHASE","LIQUIDITY_PARTNER",
 "BINANCE","KOTANI","REDPAY","MANUAL_APPROVED"
];
let cache=null,columns=null;

const json=(res,status,data)=>{
 res.status(status);res.setHeader("Content-Type","application/json");
 res.setHeader("Cache-Control","no-store");res.end(JSON.stringify(data));
};
const num=v=>Number.isFinite(Number(v))&&Number(v)>0?Number(v):null;
const integer=v=>Number.isInteger(Number(v))&&Number(v)>0?Number(v):null;
const round=(v,d=6)=>Math.round(Number(v)*10**d)/10**d;
const ref=p=>`${p}-${Date.now()}-${randomBytes(8).toString("hex").toUpperCase()}`;
const source=v=>String(v||"").trim().toUpperCase();
const validSource=v=>SOURCES.includes(source(v));
const tronAddress=a=>{
 try{return Boolean(a)&&TronWeb.isAddress(String(a).trim())}catch{return false}
};

function cookies(req){
 const r={};
 for(const x of String(req.headers?.cookie||"").split(";")){
  const i=x.indexOf("=");if(i<0)continue;
  try{r[x.slice(0,i).trim()]=decodeURIComponent(x.slice(i+1).trim())}
  catch{r[x.slice(0,i).trim()]=x.slice(i+1).trim()}
 }
 return r;
}

function same(a,b){
 const x=Buffer.from(String(a)),y=Buffer.from(String(b));
 return x.length===y.length&&timingSafeEqual(x,y);
}

function admin(req){
 const t=cookies(req)[COOKIE],s=process.env.ADMIN_SESSION_SECRET;
 if(!t||!s)return null;
 const [p,sig]=t.split(".");
 if(!p||!sig)return null;
 const expected=createHmac("sha256",s).update(p).digest("base64url");
 if(!same(sig,expected))return null;
 try{
  const x=JSON.parse(Buffer.from(p,"base64url").toString());
  return x?.id==="admin"&&x.email&&Number(x.exp)>Date.now()?x:null;
 }catch{return null}
}

function requireAdmin(req){
 const a=admin(req);
 if(!a){
  const e=new Error("Acesso permitido somente ao administrador.");
  e.statusCode=401;throw e;
 }
 return a;
}

function treasury(){
 const a=String(
  process.env.TREASURY_TRON_ADDRESS||
  process.env.USDTMZ_TRON_WALLET_ADDRESS||
  process.env.TRON_TREASURY_ADDRESS||"").trim();
 if(!tronAddress(a))throw new Error("Endereço TRON da tesouraria inválido.");
 return a;
}

function tron(){
 const o={fullHost:TRON};
 if(process.env.TRON_PRO_API_KEY)
  o.headers={"TRON-PRO-API-KEY":process.env.TRON_PRO_API_KEY};
 return new TronWeb(o);
}

async function fetchJson(url,opt={},timeout=15000){
 const c=new AbortController(),t=setTimeout(()=>c.abort(),timeout);
 try{
  const r=await fetch(url,{...opt,signal:c.signal}),txt=await r.text();
  let d={};try{d=txt?JSON.parse(txt):{}}catch{d={raw:txt}}
  if(!r.ok){
   const e=new Error(d?.message||d?.error||`HTTP ${r.status}`);
   e.status=r.status;e.data=d;throw e;
  }
  return d;
 }finally{clearTimeout(t)}
}

async function body(req){
 if(req.body&&typeof req.body==="object")return req.body;
 let s="";for await(const x of req)s+=x.toString();
 if(!s)return {};
 try{return JSON.parse(s)}catch{throw new Error("JSON inválido.")}
}

async function providerColumns(){
 if(columns)return columns;
 columns=(async()=>{
  await sql`ALTER TABLE transactions ADD COLUMN IF NOT EXISTS provider TEXT`;
  await sql`ALTER TABLE transactions ADD COLUMN IF NOT EXISTS provider_reference TEXT`;
  await sql`CREATE INDEX IF NOT EXISTS transactions_provider_reference_idx
   ON transactions(provider,provider_reference)`;
 })();
 try{await columns}catch(e){columns=null;throw e}
}

const payConfigured=()=>Boolean(
 process.env.PAY_API_KEY&&process.env.PAY_WALLET_ID&&process.env.PAY_MERCHANT_ID
);

async function pay(path,opt={}){
 if(!payConfigured())throw new Error("Pay.co.mz não está configurado.");
 return fetchJson(`${PAY}${path}`,{
  ...opt,
  headers:{
   Authorization:`Bearer ${process.env.PAY_API_KEY}`,
   "X-Wallet-Id":String(process.env.PAY_WALLET_ID),
   "X-Merchant-Id":String(process.env.PAY_MERCHANT_ID),
   Accept:"application/json",
   ...(opt.body?{"Content-Type":"application/json"}:{}),
   ...(opt.headers||{})
  }
 },20000);
}

function payMethod(v){
 v=String(v||"").toLowerCase().trim();
 if(["mpesa","mkesh","card"].includes(v))return v;
 if(v==="emola")throw new Error("e-Mola não está disponível na API Pay.co.mz configurada.");
 throw new Error("Método inválido.");
}

async function createPay(body){
 await providerColumns();
 const amount=num(body.amount_mzn??body.amount);
 if(!amount||amount<20||amount>MAX)throw new Error("Valor deve estar entre 20 e 40000 MZN.");
 const method=payMethod(body.method);
 const name=String(body.customer_name||body.name||"USDTMZ Admin").trim();
 let contact=String(body.customer_contact||body.payment_phone||body.phone||"").trim();
 if(name.length<2)throw new Error("Nome inválido.");

 if(["mpesa","mkesh"].includes(method)){
  contact=contact.replace(/\D/g,"");
  if(/^\d{9}$/.test(contact))contact="258"+contact;
  if(!/^258\d{9}$/.test(contact))throw new Error("Número M-Pesa/mKesh inválido.");
 }else if(method==="card"&&!contact)throw new Error("Contacto do cartão obrigatório.");

 const reference=String(body.reference||"").trim()||ref("PAY-TREASURY");
 if(!/^[A-Za-z0-9._:-]{8,120}$/.test(reference))throw new Error("reference inválida.");

 const old=await sql`SELECT * FROM transactions WHERE reference=${reference} LIMIT 1`;
 if(old.length)return{success:true,existing:true,reference,transaction:old[0]};

 const [tx]=await sql`
 INSERT INTO transactions(user_id,type,asset,amount,status,reference,provider,created_at)
 VALUES(NULL,'DEPOSIT_MZN','MZN',${round(amount,2)},'PENDING',${reference},'PAY_CO_MZ',NOW())
 RETURNING *`;

 let r;
 try{
  r=await pay("/charges",{
   method:"POST",
   headers:{"Idempotency-Key":`usdtmz-${reference}`},
   body:JSON.stringify({
    amount:round(amount,2),method,customer_name:name,
    customer_contact:contact,wallet_id:Number(process.env.PAY_WALLET_ID)
   })
  });
 }catch(e){
  await sql`UPDATE transactions SET status='FAILED' WHERE id=${tx.id} AND status='PENDING'`;
  throw e;
 }

 const pr=String(r?.reference||r?.charge?.reference||r?.data?.reference||
  r?.transaction_reference||r?.data?.transaction_reference||"").trim();

 if(pr)await sql`UPDATE transactions SET provider_reference=${pr} WHERE id=${tx.id}`;

 const st=String(r?.status||r?.charge?.status||r?.data?.status||"").toUpperCase();

 if(["PAID","SUCCEEDED","SUCCESS"].includes(st))
  return{success:true,created:true,confirmed:true,reference,
   providerReference:pr,pay:r,confirmation:await confirmPay({
    reference,provider_reference:pr,provider_data:r
   })};

 return{
  success:true,created:true,confirmed:false,status:st||"PROCESSING",
  reference,providerReference:pr||null,
  checkout_url:r?.checkout_url||r?.charge?.checkout_url||r?.data?.checkout_url||null,
  pay:r
 };
}

async function findPay(b){
 await providerColumns();
 const pr=String(b.provider_reference||b.transaction_reference||b.pay_reference||"").trim();
 const rr=String(b.reference||"").trim();
 if(pr){
  const x=await sql`SELECT * FROM transactions
   WHERE provider='PAY_CO_MZ' AND provider_reference=${pr}
   ORDER BY id DESC LIMIT 1`;
  if(x.length)return x[0];
 }
 if(rr){
  const x=await sql`SELECT * FROM transactions
   WHERE reference=${rr} AND type='DEPOSIT_MZN'
   ORDER BY id DESC LIMIT 1`;
  if(x.length)return x[0];
 }
 return null;
}

function payNet(data,gross){
 for(const x of[
  data?.net_amount,data?.net,data?.amount_net,
  data?.data?.net_amount,data?.charge?.net_amount
 ]){
  if(num(x))return round(x,2);
 }
 for(const x of[data?.fee,data?.fees,data?.fee_amount,data?.data?.fee,data?.charge?.fee]){
  const f=Number(x);
  if(Number.isFinite(f)&&f>=0&&f<gross)return round(gross-f,2);
 }
 throw new Error("Pay.co.mz não informou valor líquido/taxa verificável.");
}

async function confirmPay(b){
 const tx=await findPay(b);
 if(!tx)throw new Error("Transação Pay.co.mz não encontrada.");
 if(tx.status==="COMPLETED")return{success:true,confirmed:true,alreadyCompleted:true,transaction:tx};
 if(tx.status!=="PENDING")throw new Error(`Transação está em ${tx.status}.`);

 const d=b.provider_data||b.pay||{};
 const st=String(d?.status||d?.charge?.status||d?.data?.status||b.status||"").toUpperCase();
 if(st&& !["PAID","SUCCEEDED","SUCCESS","COMPLETED"].includes(st))
  throw new Error(`Pagamento ainda não confirmado: ${st}.`);

 const gross=Number(tx.amount),net=payNet(d,gross);
 if(!num(net))throw new Error("Valor líquido inválido.");

 const u=await sql`
  UPDATE transactions SET status='COMPLETED',amount=${net}
  WHERE id=${tx.id} AND status='PENDING' RETURNING *`;

 if(!u.length)return{success:true,confirmed:true,alreadyCompleted:true,reference:tx.reference};

 try{await changeWallet("MZN",net)}
 catch(e){
  await sql`UPDATE transactions SET status='PENDING',amount=${gross}
   WHERE id=${tx.id} AND status='COMPLETED'`;throw e;
 }

 return{success:true,confirmed:true,reference:tx.reference,grossAmount:gross,netAmount:net,transaction:u[0]};
}

async function payStatus(b){
 await providerColumns();
 const tx=await findPay(b);
 const r=await pay("/charges?limit=100",{method:"GET"});
 const charges=Array.isArray(r)?r:r?.charges||r?.data||r?.data?.charges||[];
 const wanted=String(b.provider_reference||b.transaction_reference||b.pay_reference||"").trim();
 const wantedLocal=String(b.reference||"").trim();

 const c=charges.find(x=>{
  const p=String(x?.reference||x?.transaction_reference||x?.id||"");
  const m=String(x?.metadata?.reference||x?.metadata?.usdtmz_reference||"");
  return wanted?p===wanted:(wantedLocal&&(p===wantedLocal||m===wantedLocal));
 });

 if(!tx)throw new Error("Operação Pay.co.mz não encontrada localmente.");
 if(!c)return{success:true,foundLocal:true,foundProvider:false,confirmed:false,transaction:tx};

 const pr=String(c.reference||c.transaction_reference||c.id||"");
 if(pr)await sql`UPDATE transactions SET provider_reference=${pr} WHERE id=${tx.id}`;

 const st=String(c.status||c.charge?.status||c.data?.status||"").toUpperCase();
 if(["PAID","SUCCEEDED","SUCCESS","COMPLETED"].includes(st))
  return confirmPay({reference:tx.reference,provider_reference:pr,provider_data:c,status:st});

 if(["FAILED","CANCELLED","CANCELED"].includes(st))
  await sql`UPDATE transactions SET status='FAILED' WHERE id=${tx.id} AND status='PENDING'`;

 return{success:true,confirmed:false,status:st||"PROCESSING",reference:tx.reference,providerReference:pr,transaction:tx};
}

function signature(v){
 const o={};for(const p of String(v||"").split(",")){
  const [k,...z]=p.split("=");if(k)o[k]=z.join("=");
 }
 return o.t&&o.v1?{timestamp:o.t,signature:o.v1}:null;
}

async function payWebhook(req,res){
 const secret=process.env.PAY_WEBHOOK_SECRET;
 if(!secret)return json(res,500,{success:false,error:"PAY_WEBHOOK_SECRET não configurado."});
 let raw="";for await(const x of req)raw+=x.toString();

 const s=signature(req.headers["x-pay-signature"]);
 if(!s)return json(res,401,{success:false,error:"Assinatura ausente."});

 const t=Number(s.timestamp),tm=t<1e10?t*1000:t;
 if(!Number.isFinite(t)||Math.abs(Date.now()-tm)>300000)
  return json(res,401,{success:false,error:"Webhook expirado."});

 const expected=createHmac("sha256",secret).update(`${s.timestamp}.${raw}`).digest("hex");
 if(!same(s.signature,expected))return json(res,401,{success:false,error:"Assinatura inválida."});

 let e;try{e=JSON.parse(raw)}catch{return json(res,400,{success:false,error:"JSON inválido."})}

 const id=String(req.headers["x-pay-event-id"]||e?.id||e?.event_id||"").trim();
 const type=String(req.headers["x-pay-event"]||e?.type||e?.event||"").trim();

 await sql`CREATE TABLE IF NOT EXISTS pay_webhook_events(
  id BIGSERIAL PRIMARY KEY,event_id TEXT UNIQUE NOT NULL,
  event_type TEXT,received_at TIMESTAMPTZ DEFAULT NOW())`;

 if(id){
  const x=await sql`INSERT INTO pay_webhook_events(event_id,event_type)
   VALUES(${id},${type}) ON CONFLICT(event_id) DO NOTHING RETURNING id`;
  if(!x.length)return json(res,200,{success:true,duplicate:true});
 }

 const d=e?.data||e?.payment||e?.charge||e;
 const pr=String(d?.reference||d?.transaction_reference||
  d?.charge?.reference||d?.payment?.reference||e?.reference||"");
 const lr=String(d?.metadata?.reference||d?.metadata?.usdtmz_reference||
  e?.metadata?.reference||e?.metadata?.usdtmz_reference||"");

 if(type==="payment.succeeded"){
  try{
   const r=await confirmPay({
    reference:lr,provider_reference:pr,
    provider_data:d,status:d?.status||"PAID"
   });
   return json(res,200,{success:true,event:type,confirmed:r.confirmed,reference:r.reference});
  }catch(err){
   console.error("PAY WEBHOOK:",err);
   return json(res,500,{success:false,error:err.message});
  }
 }

 if(type==="payment.failed"){
  const tx=await findPay({reference:lr,provider_reference:pr});
  if(tx)await sql`UPDATE transactions SET status='FAILED'
   WHERE id=${tx.id} AND status='PENDING'`;
  return json(res,200,{success:true,event:type,processed:Boolean(tx)});
 }

 return json(res,200,{success:true,ignored:true,event:type||null});
}

/* ---------- FX ---------- */

const positiveRate=v=>num(v);

async function usdMznAfrica(){
 if(!process.env.AFRICA_API_KEY)throw new Error("AFRICA_API_KEY não configurada.");
 const d=await fetchJson(
  "https://api.africa-api.com/v1/data?country_code=MZ&metric_key=official_exchange_rate_latest_lcu_per_usd&latest=true",
  {headers:{
   Authorization:`Bearer ${process.env.AFRICA_API_KEY}`,
   "X-API-Key":process.env.AFRICA_API_KEY,Accept:"application/json"
  }},10000);
 let r=d?.data?.value??d?.data?.rate??d?.value??d?.rate;
 if(Array.isArray(d?.data))r=d.data[0]?.value??d.data[0]?.rate;
 r=positiveRate(r);if(!r)throw new Error("Africa API USD/MZN inválido.");
 return{rate:r,source:"Africa-API",updatedAt:new Date().toISOString()};
}

async function usdMznOpen(){
 const d=await fetchJson("https://open.er-api.com/v6/latest/USD",{headers:{Accept:"application/json"}},10000);
 const r=positiveRate(d?.rates?.MZN);
 if(d?.result!=="success"||!r)throw new Error("OpenER USD/MZN inválido.");
 return{rate:r,source:"OpenER-API",updatedAt:d?.time_last_update_utc||new Date().toISOString()};
}

async function usdMznMoney(){
 const d=await fetchJson("https://cdn.moneyconvert.net/api/latest.json",{headers:{Accept:"application/json"}},10000);
 const r=positiveRate(d?.rates?.MZN||d?.MZN||d?.data?.rates?.MZN);
 if(!r)throw new Error("MoneyConvert USD/MZN inválido.");
 return{rate:r,source:"MoneyConvert",updatedAt:d?.date||new Date().toISOString()};
}

async function usdMzn(){
 for(const f of[usdMznAfrica,usdMznOpen,usdMznMoney])
  try{return await f()}catch{}
 throw new Error("Todas as fontes USD/MZN falharam.");
}

async function usdtUsdCoinbase(){
 const d=await fetchJson("https://api.coinbase.com/v2/exchange-rates?currency=USDT",
  {headers:{Accept:"application/json"}},10000);
 const r=positiveRate(d?.data?.rates?.USD);
 if(!r)throw new Error("Coinbase USDT/USD inválido.");
 return{rate:r,source:"Coinbase",updatedAt:new Date().toISOString()};
}

async function usdtUsdGecko(){
 const d=await fetchJson("https://api.coingecko.com/api/v3/simple/price?ids=tether&vs_currencies=usd",
  {headers:{Accept:"application/json"}},10000);
 const r=positiveRate(d?.tether?.usd);
 if(!r)throw new Error("CoinGecko USDT/USD inválido.");
 return{rate:r,source:"CoinGecko",updatedAt:new Date().toISOString()};
}

async function usdtUsd(){
 for(const f of[usdtUsdCoinbase,usdtUsdGecko])
  try{return await f()}catch{}
 throw new Error("Todas as fontes USDT/USD falharam.");
}

async function realRate(force=false){
 if(!force&&cache&&Date.now()-cache.time<60000)return cache.value;
 const a=await usdMzn(),b=await usdtUsd(),r=a.rate*b.rate;
 if(!num(r))throw new Error("Taxa cambial inválida.");
 const x={
  value:round(r),rate:round(r),marketRate:round(r),
  usdMzn:round(a.rate),usdtUsd:round(b.rate,8),
  spread:0,spreadPercent:0,source:`${a.source}+${b.source}`,
  updatedAt:new Date().toISOString(),fxUpdatedAt:a.updatedAt,warning:null
 };
 cache={time:Date.now(),value:x};return x;
}

/* ---------- TRON ---------- */

function topicAddress(x){
 x=String(x||"").replace(/^0x/,"");
 if(x.length!==64)return null;
 try{return TronWeb.address.fromHex("41"+x.slice(-40))}catch{return null}
}

function topicAmount(x){
 try{
  x=String(x||"").replace(/^0x/,"");
  if(!/^[0-9a-f]{64}$/i.test(x))return null;
  return Number(BigInt("0x"+x))/10**DEC;
 }catch{return null}
}

async function verifyUsdt(txHash,to=treasury()){
 if(!/^[a-f\d]{64}$/i.test(String(txHash||"")))throw new Error("TX hash TRON inválido.");
 const info=await tron().trx.getTransactionInfo(txHash);
 if(!info?.id)throw new Error("Transação TRON não encontrada.");
 if(info.receipt?.result&&String(info.receipt.result).toUpperCase()!=="SUCCESS")
  throw new Error("Transação TRON falhou.");

 const d=await fetchJson(
  `${TRON}/v1/transactions/${txHash}/events?only_confirmed=true`,
  {headers:{
   Accept:"application/json",
   ...(process.env.TRON_PRO_API_KEY?{"TRON-PRO-API-KEY":process.env.TRON_PRO_API_KEY}:{})
  }},15000);

 let total=0,found=false;
 for(const e of Array.isArray(d?.data)?d.data:[]){
  if(String(e.contract_address||"").toLowerCase()!==CONTRACT.toLowerCase()||
     (e.event_name||e.eventName)!=="Transfer")continue;
  const r=e.result||{},dest=r.to||r._to||r["1"];
  const address=String(dest||"").startsWith("T")?dest:topicAddress(dest);
  if(address!==to)continue;
  const v=r.value||r._value||r["2"];
  const amount=/^\d+$/.test(String(v))?
   Number(BigInt(String(v)))/10**DEC:topicAmount(v);
  if(num(amount)){total+=amount;found=true}
 }
 if(!found)throw new Error("Nenhum USDT TRC20 confirmado para a tesouraria.");
 return{confirmed:true,txHash,treasuryAddress:to,amount:round(total),contract:CONTRACT,blockNumber:info.blockNumber||null};
}

/* ---------- WALLETS ---------- */

async function wallet(asset){
 asset=String(asset).toUpperCase();
 if(!["MZN","USDT"].includes(asset))throw new Error("Asset inválido.");
 const x=await sql`SELECT * FROM wallets
  WHERE asset=${asset} AND(user_id IS NULL OR user_id=0)
  ORDER BY id LIMIT 1`;
 if(x.length)return x[0];

 const a=asset==="USDT"?treasury():null;
 const y=await sql`INSERT INTO wallets
  (wallet_address,network,asset,balance,status,created_at,updated_at,user_id)
  VALUES(${a},${asset==="USDT"?"TRON":"INTERNAL"},${asset},0,'ACTIVE',NOW(),NOW(),NULL)
  RETURNING *`;
 return y[0];
}

async function balances(){
 const r=await sql`SELECT asset,balance FROM wallets
  WHERE(user_id IS NULL OR user_id=0) AND asset IN('MZN','USDT')`;
 let m=0,u=0;
 for(const x of r){if(x.asset==="MZN")m=Number(x.balance)||0;if(x.asset==="USDT")u=Number(x.balance)||0}
 return{mzn:round(m,2),usdt:round(u)};
}

async function changeWallet(asset,amount){
 const w=await wallet(asset);
 const x=await sql`UPDATE wallets SET balance=COALESCE(balance,0)+${amount},
  updated_at=NOW() WHERE id=${w.id} RETURNING *`;
 return x[0];
}

/* ---------- DEPÓSITOS ---------- */

async function registerMzn(b){
 const amount=integer(b.amount_mzn??b.amount);
 if(!amount||amount<MIN||amount>MAX)throw new Error("Valor MZN inválido.");
 const s=source(b.source||b.method||"MANUAL_APPROVED");
 if(!validSource(s))throw new Error("Fonte inválida.");
 const reference=String(b.reference||"").trim()||ref("MZN-DEPOSIT");
 const old=await sql`SELECT * FROM transactions WHERE reference=${reference} LIMIT 1`;
 if(old.length)return{success:true,existing:true,transaction:old[0]};
 const x=await sql`INSERT INTO transactions
  (user_id,type,asset,amount,status,reference,created_at)
  VALUES(NULL,'DEPOSIT_MZN','MZN',${amount},'PENDING',${reference},NOW()) RETURNING *`;
 return{success:true,confirmed:false,reference,transaction:x[0]};
}

async function confirmMzn(b){
 const reference=String(b.reference||"").trim();
 if(!reference)throw new Error("reference obrigatória.");
 const x=await sql`SELECT * FROM transactions
  WHERE reference=${reference} AND type='DEPOSIT_MZN'
  ORDER BY id DESC LIMIT 1`;
 if(!x.length)throw new Error("Depósito MZN não encontrado.");
 const t=x[0];
 if(t.status==="COMPLETED")return{success:true,confirmed:true,alreadyCompleted:true,transaction:t};
 if(t.status!=="PENDING")throw new Error(`Depósito está em ${t.status}.`);

 const u=await sql`UPDATE transactions SET status='COMPLETED'
  WHERE id=${t.id} AND status='PENDING' RETURNING *`;
 if(!u.length)return{success:true,confirmed:true,alreadyCompleted:true};

 try{await changeWallet("MZN",Number(t.amount))}
 catch(e){
  await sql`UPDATE transactions SET status='PENDING' WHERE id=${t.id} AND status='COMPLETED'`;
  throw e;
 }
 return{success:true,confirmed:true,reference,amount:Number(t.amount),transaction:u[0]};
}

async function registerUsdt(b){
 const hash=String(b.tx_hash||b.txHash||b.blockchain_tx_hash||"").trim();
 if(!/^[a-f\d]{64}$/i.test(hash))throw new Error("TX hash TRON inválido.");
 const reference=String(b.reference||"").trim()||ref("USDT-DEPOSIT");
 const old=await sql`SELECT * FROM transactions
  WHERE blockchain_tx_hash=${hash} OR reference=${reference}
  ORDER BY id LIMIT 1`;
 if(old.length)return{success:true,existing:true,transaction:old[0]};
 const x=await sql`INSERT INTO transactions
  (user_id,type,asset,amount,status,reference,blockchain_tx_hash,created_at)
  VALUES(NULL,'DEPOSIT_USDT','USDT',0,'PENDING',${reference},${hash},NOW()) RETURNING *`;
 return{success:true,confirmed:false,reference,transaction:x[0]};
}

async function confirmUsdt(b){
 let hash=String(b.tx_hash||b.txHash||"").trim(),t=null;
 const reference=String(b.reference||"").trim();

 if(reference){
  const x=await sql`SELECT * FROM transactions
   WHERE reference=${reference} AND type='DEPOSIT_USDT'
   ORDER BY id DESC LIMIT 1`;
  if(x.length){t=x[0];hash=hash||String(t.blockchain_tx_hash||"")}
 }
 if(!hash)throw new Error("TX hash obrigatório.");

 const v=await verifyUsdt(hash);

 if(!t){
  const x=await sql`SELECT * FROM transactions
   WHERE blockchain_tx_hash=${hash} AND type='DEPOSIT_USDT'
   ORDER BY id DESC LIMIT 1`;
  t=x[0]||null;
 }

 if(t?.status==="COMPLETED")return{success:true,confirmed:true,alreadyCompleted:true,blockchain:v,transaction:t};

 if(!t){
  const x=await sql`INSERT INTO transactions
   (user_id,type,asset,amount,status,reference,blockchain_tx_hash,created_at)
   VALUES(NULL,'DEPOSIT_USDT','USDT',${v.amount},'COMPLETED',
   ${reference||ref("USDT-DEPOSIT")},${hash},NOW()) RETURNING *`;
  try{await changeWallet("USDT",v.amount)}
  catch(e){await sql`DELETE FROM transactions WHERE id=${x[0].id}`;throw e}
  return{success:true,confirmed:true,blockchain:v,transaction:x[0]};
 }

 const u=await sql`UPDATE transactions SET status='COMPLETED',
  amount=${v.amount},blockchain_tx_hash=${hash}
  WHERE id=${t.id} AND status='PENDING' RETURNING *`;
 if(!u.length)return{success:true,confirmed:true,alreadyCompleted:true,blockchain:v};

 try{await changeWallet("USDT",v.amount)}
 catch(e){
  await sql`UPDATE transactions SET status='PENDING',amount=${t.amount}
   WHERE id=${t.id} AND status='COMPLETED'`;throw e;
 }
 return{success:true,confirmed:true,blockchain:v,transaction:u[0]};
}

/* ---------- LIQUIDEZ / CONVERSÃO ---------- */

async function liquidity(amount){
 const n=num(amount);if(!n)throw new Error("Quantidade USDT inválida.");
 const b=await balances();
 return b.usdt>=n
 ?{available:true,executable:true,source:"TREASURY_TRON",availableUsdt:b.usdt,requiredUsdt:n}
 :{available:false,executable:false,source:null,availableUsdt:b.usdt,
   requiredUsdt:n,missingUsdt:round(n-b.usdt),
   message:"Não existe USDT real suficiente na tesouraria."};
}

async function convert(b){
 const m=integer(b.amount_mzn??b.amount);
 if(!m||m<MIN||m>MAX)throw new Error("Valor MZN inválido.");
 const rate=await realRate(),u=round(m/rate.value);
 if(!u)throw new Error("Quantidade USDT inválida.");

 const l=await liquidity(u);if(!l.available)throw new Error(l.message);
 const bal=await balances();if(bal.mzn<m)throw new Error("Fundo MZN insuficiente.");

 const reference=String(b.reference||"").trim()||ref("CONVERSION");
 const old=await sql`SELECT * FROM transactions WHERE reference=${reference} LIMIT 1`;
 if(old.length)return{success:true,existing:true,transaction:old[0]};

 const dm=await sql`UPDATE wallets SET balance=balance-${m},updated_at=NOW()
  WHERE asset='MZN' AND(user_id IS NULL OR user_id=0) AND balance>=${m} RETURNING *`;
 if(!dm.length)throw new Error("Não foi possível debitar MZN.");

 const du=await sql`UPDATE wallets SET balance=balance-${u},updated_at=NOW()
  WHERE asset='USDT' AND(user_id IS NULL OR user_id=0) AND balance>=${u} RETURNING *`;

 if(!du.length){
  await sql`UPDATE wallets SET balance=balance+${m},updated_at=NOW()
   WHERE asset='MZN' AND(user_id IS NULL OR user_id=0)`;
  throw new Error("USDT insuficiente.");
 }

 try{
  const t=await sql`INSERT INTO transactions
   (user_id,type,asset,amount,status,reference,created_at)
   VALUES(NULL,'CONVERSION_MZN_USDT','USDT',${u},'COMPLETED',${reference},NOW())
   RETURNING *`;
  return{
   success:true,reference,input:{amountMzn:m},output:{amountUsdt:u},
   liquidity:{source:"TREASURY_TRON",executable:true,realUsdt:true},
   rate:{rate:rate.value,marketRate:rate.marketRate,usdMzn:rate.usdMzn,
    usdtUsd:rate.usdtUsd,source:rate.source,spread:0,spreadPercent:0,
    updatedAt:rate.updatedAt},
   transaction:t[0]
  };
 }catch(e){
  await sql`UPDATE wallets SET balance=balance+${m},updated_at=NOW()
   WHERE asset='MZN' AND(user_id IS NULL OR user_id=0)`;
  await sql`UPDATE wallets SET balance=balance+${u},updated_at=NOW()
   WHERE asset='USDT' AND(user_id IS NULL OR user_id=0)`;
  throw e;
 }
}

/* ---------- RESERVA ---------- */

async function reserve(amount,reference){
 const n=num(amount);if(!n)throw new Error("USDT inválido.");
 const r=String(reference||"").trim()||ref("USDT-RESERVE");
 const old=await sql`SELECT * FROM transactions
  WHERE reference=${r} AND type='USDT_RESERVATION' LIMIT 1`;
 if(old.length)return{success:true,existing:true,transaction:old[0]};

 const b=await balances();
 const x=await sql`SELECT COALESCE(SUM(amount),0) reserved
  FROM transactions WHERE type='USDT_RESERVATION' AND status='PENDING'`;
 const available=Math.max(0,b.usdt-Number(x[0].reserved||0));
 if(available<n)throw new Error(`USDT disponível insuficiente: ${round(available)}.`);

 const t=await sql`INSERT INTO transactions
  (user_id,type,asset,amount,status,reference,created_at)
  VALUES(NULL,'USDT_RESERVATION','USDT',${n},'PENDING',${r},NOW()) RETURNING *`;
 return{success:true,reference:r,reserved:n,transaction:t[0]};
}

async function release(b){
 const r=String(b.reference||b.reservation_reference||"").trim();
 if(!r)throw new Error("reference obrigatória.");
 const x=await sql`SELECT * FROM transactions
  WHERE reference=${r} AND type='USDT_RESERVATION' LIMIT 1`;
 if(!x.length)throw new Error("Reserva não encontrada.");
 if(x[0].status!=="PENDING")return{success:true,alreadyProcessed:true,transaction:x[0]};
 const u=await sql`UPDATE transactions SET status='CANCELLED'
  WHERE id=${x[0].id} AND status='PENDING' RETURNING *`;
 return{success:true,released:Number(x[0].amount),transaction:u[0]||x[0]};
}

/* ---------- FUNDING ---------- */

async function funding(b){
 const asset=String(b.asset||"").toUpperCase(),amount=num(b.amount);
 if(!["MZN","USDT"].includes(asset)||!amount)throw new Error("Funding inválido.");
 const s=source(b.source||"MANUAL_APPROVED");
 if(!validSource(s))throw new Error("Fonte inválida.");
 const r=String(b.reference||"").trim()||ref("FUNDING");

 const old=await sql`SELECT * FROM transactions WHERE reference=${r} LIMIT 1`;
 if(old.length)return{success:true,existing:true,transaction:old[0]};

 if(asset==="USDT"){
  const hash=String(b.tx_hash||b.txHash||b.blockchain_tx_hash||"").trim();
  if(!/^[a-f\d]{64}$/i.test(hash))throw new Error("Funding USDT exige TX hash TRON real.");
  const v=await verifyUsdt(hash);
  if(round(v.amount)!==round(amount))throw new Error("Valor da TX não corresponde ao funding.");

  const d=await sql`SELECT * FROM transactions WHERE blockchain_tx_hash=${hash} LIMIT 1`;
  if(d.length)return{success:true,existing:true,transaction:d[0]};

  const t=await sql`INSERT INTO transactions
   (user_id,type,asset,amount,status,reference,blockchain_tx_hash,created_at)
   VALUES(NULL,'FUNDING','USDT',${v.amount},'COMPLETED',${r},${hash},NOW()) RETURNING *`;
  try{await changeWallet("USDT",v.amount)}
  catch(e){await sql`DELETE FROM transactions WHERE id=${t[0].id}`;throw e}
  return{success:true,reference:r,amount:v.amount,asset,source:s,blockchain:v,transaction:t[0]};
 }

 const t=await sql`INSERT INTO transactions
  (user_id,type,asset,amount,status,reference,created_at)
  VALUES(NULL,'FUNDING','MZN',${amount},'PENDING',${r},NOW()) RETURNING *`;
 return{success:true,confirmed:false,reference:r,amount,asset,source:s,transaction:t[0]};
}

/* ---------- DASHBOARD ---------- */

async function dashboard(){
 const b=await balances();
 let rate;try{rate=await realRate()}catch(e){rate={error:e.message}};
 let address=null;try{address=treasury()}catch{}
 let trx=0;
 if(address)try{trx=Number(await tron().trx.getBalance(address))/1e6}catch{}

 const x=await sql`SELECT COALESCE(SUM(amount),0) reserved
  FROM transactions WHERE type='USDT_RESERVATION' AND status='PENDING'`;
 const reserved=Number(x[0]?.reserved||0),available=Math.max(0,b.usdt-reserved);

 return{
  success:true,
  treasury:{
   mzn:b.mzn,usdt:b.usdt,trx:round(trx),
   reservedUsdt:round(reserved),availableUsdt:round(available),
   state:available>0&&b.mzn>0?"LIQUIDEZ DISPONÍVEL":
    available>0?"USDT DISPONÍVEL":b.mzn>0?"MZN DISPONÍVEL":"SEM LIQUIDEZ"
  },
  wallet:{address,network:"TRON Mainnet",asset:"USDT",standard:"TRC-20",contract:CONTRACT},
  rate
 };
}

async function operations(){
 return{success:true,operations:await sql`
 SELECT id,user_id,type,asset,amount,status,reference,provider,
 provider_reference,blockchain_tx_hash,created_at
 FROM transactions ORDER BY id DESC LIMIT 50`};
}

async function pending(){
 return{success:true,deposits:await sql`
 SELECT id,type,asset,amount,status,reference,provider,
 provider_reference,blockchain_tx_hash,created_at
 FROM transactions WHERE status='PENDING' ORDER BY id LIMIT 100`};
}

async function sources(){
 const b=await balances(),a=(()=>{try{return treasury()}catch{return null}})();
 const e={
  binance:Boolean(process.env.BINANCE_API_KEY&&process.env.BINANCE_API_SECRET),
  kotani:Boolean(process.env.KOTANI_API_KEY),
  redpay:Boolean(process.env.REDPAY_API_KEY)
 };
 return{
  success:true,
  policy:{
   artificialSpread:false,usdtPegFallback:false,fixedUsdtMznRate:false,
   marketRateRequired:true,realLiquidityRequired:true
  },
  sources:[
   {id:"TREASURY_TRON",type:"USDT_TRON",name:"Tesouraria USDTMZ",
    configured:Boolean(a),executionAvailable:Boolean(a),address:a,asset:"USDT",network:"TRON/TRC20",balance:b.usdt},
   {id:"PAY_MPESA",type:"MPESA_BUSINESS",name:"Pay.co.mz — M-Pesa",
    configured:payConfigured(),executionAvailable:payConfigured(),asset:"MZN"},
   {id:"PAY_MKESH",type:"MKESH_BUSINESS",name:"Pay.co.mz — mKesh",
    configured:payConfigured(),executionAvailable:payConfigured(),asset:"MZN"},
   {id:"PAY_EMOLA",type:"EMOLA_BUSINESS",name:"Pay.co.mz — e-Mola",
    configured:false,executionAvailable:false,asset:"MZN"},
   {id:"PAY_CARD",type:"CARD",name:"Pay.co.mz — Visa/Mastercard",
    configured:payConfigured(),executionAvailable:payConfigured(),asset:"MZN"},
   {id:"BINANCE",type:"BINANCE",name:"Binance",configured:e.binance,
    executionAvailable:false,asset:"USDT",network:"TRON/TRC20"},
   {id:"KOTANI",type:"KOTANI",name:"Kotani",configured:e.kotani,
    executionAvailable:false,asset:"USDT"},
   {id:"REDPAY",type:"REDPAY",name:"RedPay",configured:e.redpay,
    executionAvailable:false,asset:"USDT"}
  ]
 };
}

/* ---------- ROUTER ---------- */

export default async function handler(req,res){
 try{
  const u=new URL(req.url,"http://localhost");
  const urlAction=String(u.searchParams.get("action")||"").toLowerCase();
  const webhook=urlAction==="pay_webhook"||req.headers["x-pay-signature"];
  if(webhook)return payWebhook(req,res);

  const a=requireAdmin(req);
  if(!["GET","POST"].includes(req.method))
   return json(res,405,{success:false,error:"Método não permitido."});

  const b=req.method==="POST"?await body(req):{};
  const action=String(b.action||urlAction||"dashboard").toLowerCase();

  const actions={
   rate:()=>({success:true,data:realRate(false)}),
   exchange_rate:()=>({success:true,data:realRate(false)}),
   fx_rate:()=>({success:true,data:realRate(false)}),
   refresh_rate:()=>({success:true,data:realRate(true)}),
   update_rate:()=>({success:true,data:realRate(true)}),
   dashboard,
   sources,liquidity_sources:sources,
   operations,recent_operations:operations,
   pending_deposits:pending,
   create_pay_treasury_charge:()=>createPay(b),
   pay_treasury_charge:()=>createPay(b),
   create_pagar_treasury_topup:()=>createPay(b),
   check_pay_treasury_charge:()=>payStatus(b),
   pay_treasury_status:()=>payStatus(b),
   check_pagar_treasury_topup:()=>payStatus(b),
   register_mzn_deposit:()=>registerMzn(b),
   confirm_mzn_deposit:()=>confirmMzn(b),
   register_usdt_deposit:()=>registerUsdt(b),
   confirm_usdt_deposit:()=>confirmUsdt(b),
   convert_mzn_to_usdt:()=>convert(b),
   reserve_usdt:()=>reserve(b.amount_usdt??b.amount,b.reference||ref("USDT-RESERVE")),
   release_reservation:()=>release(b),
   register_funding:()=>funding(b)
  };

  if(!actions[action])
   return json(res,400,{success:false,error:`Ação "${action}" não reconhecida.`,admin:a.email});

  return json(res,200,await actions[action]());
 }catch(e){
  console.error("USDTMZ API06:",e);
  const s=Number(e.statusCode||e.status||500);
  return json(res,s>=400&&s<600?s:500,{success:false,error:e.message||"Erro interno."});
 }
}
