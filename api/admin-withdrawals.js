// api/admin-withdrawals.js
// USDTMZ — API06 CENTRAL ADMIN / TESOURARIA
// Mantém as 12 APIs. NÃO criar API13.

import{createHmac,timingSafeEqual,randomBytes}from"node:crypto";
import{neon}from"@neondatabase/serverless";
import{TronWeb}from"tronweb";

const sql=neon(process.env.DATABASE_URL);
const COOKIE="usdtmz_admin_session",MIN=64,MAX=40000,DEC=6;
const CONTRACT=process.env.USDT_TRON_CONTRACT||
"TR7NHqjeKQXGTCi8q8ZY4pL8otSzgjLj6t";
const TRON=process.env.TRON_HOST||"https://api.trongrid.io";
const PAY=process.env.PAY_API_BASE_URL||"https://pay.co.mz/api/public/v1";
const SOURCES=["MPESA_BUSINESS","MKESH_BUSINESS","EMOLA_BUSINESS","BANK",
"USDT_TRON","EXTERNAL_WALLET","USDT_PURCHASE","LIQUIDITY_PARTNER",
"BINANCE","KOTANI","REDPAY","MANUAL_APPROVED"];
let cache=null,cols;

const json=(r,s,d)=>{r.status(s);r.setHeader("Content-Type","application/json");
r.setHeader("Cache-Control","no-store");r.end(JSON.stringify(d))};
const n=v=>Number.isFinite(Number(v))&&Number(v)>0?Number(v):null;
const ri=v=>Number.isInteger(Number(v))&&Number(v)>0?Number(v):null;
const rnd=(v,d=6)=>Math.round(Number(v)*10**d)/10**d;
const ref=p=>`${p}-${Date.now()}-${randomBytes(6).toString("hex").toUpperCase()}`;
const src=v=>String(v||"").trim().toUpperCase();
const validSrc=v=>SOURCES.includes(src(v));

function addr(a){try{return!!a&&TronWeb.isAddress(String(a).trim())}catch{return false}}
function cookie(req){const o={};for(const x of String(req.headers?.cookie||"").split(";")){
 const i=x.indexOf("=");if(i<0)continue;o[x.slice(0,i).trim()]=decodeURIComponent(x.slice(i+1).trim())}return o}
function safe(a,b){const x=Buffer.from(String(a)),y=Buffer.from(String(b));
 return x.length===y.length&&timingSafeEqual(x,y)}
function admin(req){
 const t=cookie(req)[COOKIE],k=process.env.ADMIN_SESSION_SECRET;if(!t||!k)return null;
 const[p,s]=t.split(".");if(!p||!s)return null;
 if(!safe(s,createHmac("sha256",k).update(p).digest("base64url")))return null;
 try{const x=JSON.parse(Buffer.from(p,"base64url").toString());
 return x?.id==="admin"&&x.email&&Number(x.exp)>Date.now()?x:null}catch{return null}
}
function auth(req){const a=admin(req);if(!a){const e=new Error("Acesso somente ao administrador.");e.statusCode=401;throw e}return a}
function treasury(){
 const a=String(process.env.TREASURY_TRON_ADDRESS||
 process.env.USDTMZ_TRON_WALLET_ADDRESS||process.env.TRON_TREASURY_ADDRESS||"").trim();
 if(!addr(a))throw new Error("Endereço TRON da tesouraria inválido.");return a
}
function tron(){
 const o={fullHost:TRON};
 if(process.env.TRON_PRO_API_KEY)o.headers={"TRON-PRO-API-KEY":process.env.TRON_PRO_API_KEY};
 return new TronWeb(o)
}
async function fetchJ(url,opt={},ms=15000){
 const c=new AbortController(),t=setTimeout(()=>c.abort(),ms);
 try{const r=await fetch(url,{...opt,signal:c.signal}),z=await r.text();let d={};
 try{d=z?JSON.parse(z):{}}catch{d={raw:z}}
 if(!r.ok){const e=new Error(d?.message||d?.error||`HTTP ${r.status}`);e.status=r.status;throw e}
 return d}finally{clearTimeout(t)}
}
async function body(req){
 if(req.body&&typeof req.body==="object")return req.body;
 let s="";for await(const x of req)s+=x;
 if(!s)return{};try{return JSON.parse(s)}catch{throw new Error("JSON inválido.")}
}
async function columns(){
 if(cols)return cols;
 cols=(async()=>{
  await sql`ALTER TABLE transactions ADD COLUMN IF NOT EXISTS provider TEXT`;
  await sql`ALTER TABLE transactions ADD COLUMN IF NOT EXISTS provider_reference TEXT`;
  await sql`CREATE INDEX IF NOT EXISTS transactions_provider_reference_idx
  ON transactions(provider,provider_reference)`;
 })();
 try{await cols}catch(e){cols=null;throw e}
}
const payOK=()=>!!(process.env.PAY_API_KEY&&process.env.PAY_WALLET_ID&&process.env.PAY_MERCHANT_ID);

async function pay(path,opt={}){
 if(!payOK())throw new Error("Pay.co.mz não está configurado.");
 return fetchJ(`${PAY}${path}`,{...opt,headers:{
  Authorization:`Bearer ${process.env.PAY_API_KEY}`,
  "X-Wallet-Id":String(process.env.PAY_WALLET_ID),
  "X-Merchant-Id":String(process.env.PAY_MERCHANT_ID),
  Accept:"application/json",...(opt.body?{"Content-Type":"application/json"}:{}),
  ...(opt.headers||{})}},20000)
}
function method(v){
 v=String(v||"").toLowerCase().trim();
 if(["mpesa","mkesh","card"].includes(v))return v;
 if(v==="emola")throw new Error("e-Mola ainda não está ativo no PAY.");
 throw new Error("Método de pagamento inválido.")
}
async function createPay(b){
 await columns();
 const amount=n(b.amount_mzn??b.amount);
 if(!amount||amount<MIN||amount>MAX)throw new Error("Valor entre 64 e 40000 MZN.");
 const m=method(b.method),name=String(b.customer_name||b.name||"USDTMZ Admin").trim();
 let phone=String(b.customer_contact||b.payment_phone||b.phone||"").replace(/\D/g,"");
 if(name.length<2)throw new Error("Nome inválido.");
 if(["mpesa","mkesh"].includes(m)){
  if(/^\d{9}$/.test(phone))phone="258"+phone;
  if(!/^258\d{9}$/.test(phone))throw new Error("Número M-Pesa/mKesh inválido.");
 }
 if(m==="card"&&!phone)throw new Error("Contacto obrigatório para cartão.");
 const r=String(b.reference||"").trim()||ref("PAY-TREASURY");
 const old=await sql`SELECT * FROM transactions WHERE reference=${r} LIMIT 1`;
 if(old.length)return{success:true,existing:true,transaction:old[0]};
 const[t]=await sql`INSERT INTO transactions
 (user_id,type,asset,amount,status,reference,provider,created_at)
 VALUES(NULL,'DEPOSIT_MZN','MZN',${rnd(amount,2)},'PENDING',${r},'PAY_CO_MZ',NOW()) RETURNING *`;
 try{
  const p=await pay("/charges",{method:"POST",
   headers:{"Idempotency-Key":`usdtmz-${r}`},
   body:JSON.stringify({amount:rnd(amount,2),method:m,customer_name:name,
   customer_contact:phone,wallet_id:Number(process.env.PAY_WALLET_ID)})});
  const pr=String(p?.reference||p?.charge?.reference||p?.data?.reference||"").trim();
  if(pr)await sql`UPDATE transactions SET provider_reference=${pr} WHERE id=${t.id}`;
  return{success:true,created:true,confirmed:false,reference:r,
   providerReference:pr||null,status:String(p?.status||"PROCESSING"),
   checkout_url:p?.checkout_url||p?.charge?.checkout_url||null,pay:p};
 }catch(e){
  await sql`UPDATE transactions SET status='FAILED' WHERE id=${t.id} AND status='PENDING'`;
  throw e
 }
}
async function findPay(b){
 await columns();
 const p=String(b.provider_reference||b.transaction_reference||b.pay_reference||"").trim();
 const r=String(b.reference||"").trim();
 if(p){const x=await sql`SELECT * FROM transactions WHERE provider='PAY_CO_MZ'
 AND provider_reference=${p} ORDER BY id DESC LIMIT 1`;if(x.length)return x[0]}
 if(r){const x=await sql`SELECT * FROM transactions WHERE reference=${r}
 AND type='DEPOSIT_MZN' ORDER BY id DESC LIMIT 1`;if(x.length)return x[0]}
 return null
}
function payNet(d,gross){
 for(const x of[d?.net_amount,d?.net,d?.amount_net,d?.data?.net_amount,d?.charge?.net_amount])
  if(Number.isFinite(Number(x))&&Number(x)>0)return rnd(x,2);
 for(const x of[d?.fee,d?.fees,d?.fee_amount,d?.data?.fee,d?.charge?.fee]){
  const f=Number(x);if(Number.isFinite(f)&&f>=0&&f<gross)return rnd(gross-f,2)
 }
 throw new Error("PAY não informou o valor líquido confirmado.")
}
async function confirmPay(b){
 const t=await findPay(b);if(!t)throw new Error("Pagamento PAY não encontrado.");
 if(t.status==="COMPLETED")return{success:true,confirmed:true,alreadyCompleted:true,transaction:t};
 if(t.status!=="PENDING")throw new Error(`Transação está em ${t.status}.`);
 const d=b.provider_data||b.pay||{},st=String(d?.status||d?.state||
 d?.charge?.status||d?.data?.status||b.status||"").toUpperCase();
 if(!["PAID","SUCCEEDED","SUCCESS","COMPLETED","SUCCESSFUL"].includes(st))
  throw new Error(`Pagamento não confirmado: ${st||"PENDING"}`);
 const net=payNet(d,Number(t.amount));
 const u=await sql`UPDATE transactions SET status='COMPLETED',amount=${net}
 WHERE id=${t.id} AND status='PENDING' RETURNING *`;
 if(!u.length)return{success:true,confirmed:true,alreadyCompleted:true};
 try{await walletChange("MZN",net)}catch(e){
  await sql`UPDATE transactions SET status='PENDING',amount=${t.amount}
  WHERE id=${t.id} AND status='COMPLETED'`;throw e}
 return{success:true,confirmed:true,reference:t.reference,grossAmount:Number(t.amount),
 netAmount:net,transaction:u[0]}
}
async function payStatus(b){
 const t=await findPay(b);if(!t)throw new Error("Operação PAY não encontrada.");
 const r=await pay("/charges?limit=100"),a=Array.isArray(r)?r:r?.charges||r?.data||[];
 const wanted=String(b.provider_reference||b.transaction_reference||b.pay_reference||"").trim();
 const c=a.find(x=>String(x?.reference||x?.transaction_reference||x?.id||"")===wanted);
 if(!c)return{success:true,foundProvider:false,confirmed:false,transaction:t};
 const pr=String(c.reference||c.transaction_reference||c.id||"");
 if(pr)await sql`UPDATE transactions SET provider_reference=${pr} WHERE id=${t.id}`;
 const st=String(c.status||c.state||"").toUpperCase();
 if(["PAID","SUCCEEDED","SUCCESS","COMPLETED","SUCCESSFUL"].includes(st))
  return confirmPay({reference:t.reference,provider_reference:pr,provider_data:c,status:st});
 if(["FAILED","CANCELLED","CANCELED"].includes(st))
  await sql`UPDATE transactions SET status='FAILED' WHERE id=${t.id} AND status='PENDING'`;
 return{success:true,confirmed:false,status:st||"PROCESSING",reference:t.reference,transaction:t}
}
function sig(v){const o={};for(const p of String(v||"").split(",")){const[k,...z]=p.split("=");if(k)o[k]=z.join("=")}
 return o.t&&o.v1?o:null}
async function webhook(req,res){
 const secret=process.env.PAY_WEBHOOK_SECRET;if(!secret)return json(res,500,{success:false,error:"PAY_WEBHOOK_SECRET não configurado."});
 let raw="";for await(const x of req)raw+=x;
 const s=sig(req.headers["x-pay-signature"]);if(!s)return json(res,401,{success:false,error:"Assinatura ausente."});
 const tm=Number(s.t)<1e10?Number(s.t)*1000:Number(s.t);
 if(!Number.isFinite(tm)||Math.abs(Date.now()-tm)>300000)return json(res,401,{success:false,error:"Webhook expirado."});
 const h=createHmac("sha256",secret).update(`${s.t}.${raw}`).digest("hex");
 if(!safe(s.v1,h))return json(res,401,{success:false,error:"Assinatura inválida."});
 let e;try{e=JSON.parse(raw)}catch{return json(res,400,{success:false,error:"JSON inválido."})}
 const type=String(req.headers["x-pay-event"]||e?.event||e?.type||"");
 const d=e?.data||e?.payment||e?.charge||e;
 const pr=String(d?.reference||d?.transaction_reference||"");
 const lr=String(d?.metadata?.reference||d?.metadata?.usdtmz_reference||"");
 if(type==="payment.succeeded"){
  try{return json(res,200,{success:true,event:type,
   ...(await confirmPay({reference:lr,provider_reference:pr,
   provider_data:{...d,status:d?.status||"SUCCESS"}}))})}
  catch(x){console.error("PAY WEBHOOK",x);return json(res,500,{success:false,error:x.message})}
 }
 if(type==="payment.failed"){
  const t=await findPay({reference:lr,provider_reference:pr});
  if(t)await sql`UPDATE transactions SET status='FAILED' WHERE id=${t.id} AND status='PENDING'`;
 }
 return json(res,200,{success:true,event:type||null})
}

/* FX */
async function rateURL(url,key,source){
 const d=await fetchJ(url,{headers:{Accept:"application/json"}},10000);
 const r=n(key(d));if(!r)throw new Error("Taxa inválida.");return{rate:r,source,updatedAt:new Date().toISOString()}
}
async function usdMzn(){
 if(process.env.AFRICA_API_KEY)try{return await rateURL(
 "https://api.africa-api.com/v1/data?country_code=MZ&metric_key=official_exchange_rate_latest_lcu_per_usd&latest=true",
 d=>d?.data?.value??d?.data?.rate??d?.value,"Africa-API")}catch{}
 try{return await rateURL("https://open.er-api.com/v6/latest/USD",d=>d?.rates?.MZN,"OpenER-API")}catch{}
 return rateURL("https://cdn.moneyconvert.net/api/latest.json",
 d=>d?.rates?.MZN??d?.MZN,"MoneyConvert")
}
async function usdtUsd(){
 try{return await rateURL("https://api.coinbase.com/v2/exchange-rates?currency=USDT",
 d=>d?.data?.rates?.USD,"Coinbase")}catch{}
 return rateURL("https://api.coingecko.com/api/v3/simple/price?ids=tether&vs_currencies=usd",
 d=>d?.tether?.usd,"CoinGecko")
}
async function realRate(force=false){
 if(!force&&cache&&Date.now()-cache.t<60000)return cache.v;
 const[a,b]=await Promise.all([usdMzn(),usdtUsd()]),v=rnd(a.rate*b.rate);
 cache={t:Date.now(),v:{value:v,rate:v,marketRate:v,usdMzn:rnd(a.rate),
 usdtUsd:rnd(b.rate,8),spread:0,spreadPercent:0,
 source:`${a.source}+${b.source}`,updatedAt:new Date().toISOString(),
 fxUpdatedAt:a.updatedAt}};return cache.v
}

/* TRON */
async function verify(hash,to=treasury()){
 if(!/^[a-f\d]{64}$/i.test(String(hash||"")))throw new Error("TX TRON inválida.");
 const info=await tron().trx.getTransactionInfo(hash);
 if(!info?.id)throw new Error("Transação TRON não encontrada.");
 if(String(info.receipt?.result||"SUCCESS").toUpperCase()!=="SUCCESS")throw new Error("Transação TRON falhou.");
 const d=await fetchJ(`${TRON}/v1/transactions/${hash}/events?only_confirmed=true`,
 {headers:{Accept:"application/json",...(process.env.TRON_PRO_API_KEY?{"TRON-PRO-API-KEY":process.env.TRON_PRO_API_KEY}:{})}});
 let total=0;
 for(const e of d?.data||[]){
  if(String(e.contract_address||"").toLowerCase()!==CONTRACT.toLowerCase()||
  String(e.event_name||e.eventName)!=="Transfer")continue;
  const z=e.result||{},tox=z.to||z._to||z["1"];
  let destination=String(tox||"");
  if(!destination.startsWith("T")&&/^[0-9a-f]{64}$/i.test(destination))
   try{destination=TronWeb.address.fromHex("41"+destination.slice(-40))}catch{}
  const val=z.value||z._value||z["2"];
  if(destination===to&&/^\d+$/.test(String(val)))total+=Number(BigInt(String(val)))/10**DEC;
 }
 if(!total)throw new Error("Nenhum USDT confirmado para a tesouraria.");
 return{confirmed:true,txHash:hash,amount:rnd(total),treasuryAddress:to,contract:CONTRACT,blockNumber:info.blockNumber||null}
}

/* WALLET */
async function wallet(asset){
 asset=String(asset).toUpperCase();if(!["MZN","USDT"].includes(asset))throw new Error("Asset inválido.");
 const x=await sql`SELECT * FROM wallets WHERE asset=${asset}
 AND(user_id IS NULL OR user_id=0) ORDER BY id LIMIT 1`;if(x.length)return x[0];
 return(await sql`INSERT INTO wallets(wallet_address,network,asset,balance,status,created_at,updated_at,user_id)
 VALUES(${asset==="USDT"?treasury():null},${asset==="USDT"?"TRON":"INTERNAL"},${asset},0,'ACTIVE',NOW(),NOW(),NULL) RETURNING *`)[0]
}
async function balances(){
 const a=await sql`SELECT asset,balance FROM wallets WHERE(user_id IS NULL OR user_id=0)
 AND asset IN('MZN','USDT')`;let m=0,u=0;
 for(const x of a)x.asset==="MZN"?m=Number(x.balance)||0:u=Number(x.balance)||0;
 return{mzn:rnd(m,2),usdt:rnd(u)}
}
async function walletChange(asset,amount){
 const w=await wallet(asset);
 const x=await sql`UPDATE wallets SET balance=COALESCE(balance,0)+${amount},updated_at=NOW()
 WHERE id=${w.id} RETURNING *`;return x[0]
}

/* DEPÓSITOS */
async function registerMzn(b){
 const a=ri(b.amount_mzn??b.amount);if(!a||a<MIN||a>MAX)throw new Error("MZN inválido.");
 const s=src(b.source||b.method||"MANUAL_APPROVED");if(!validSrc(s))throw new Error("Fonte inválida.");
 const r=String(b.reference||"").trim()||ref("MZN-DEPOSIT");
 const o=await sql`SELECT * FROM transactions WHERE reference=${r} LIMIT 1`;
 if(o.length)return{success:true,existing:true,transaction:o[0]};
 const t=await sql`INSERT INTO transactions(user_id,type,asset,amount,status,reference,created_at)
 VALUES(NULL,'DEPOSIT_MZN','MZN',${a},'PENDING',${r},NOW()) RETURNING *`;
 return{success:true,confirmed:false,reference:r,transaction:t[0]}
}
async function confirmMzn(b){
 const r=String(b.reference||"").trim();if(!r)throw new Error("reference obrigatória.");
 const x=await sql`SELECT * FROM transactions WHERE reference=${r} AND type='DEPOSIT_MZN'
 ORDER BY id DESC LIMIT 1`;if(!x.length)throw new Error("Depósito não encontrado.");
 const t=x[0];if(t.status==="COMPLETED")return{success:true,confirmed:true,alreadyCompleted:true,transaction:t};
 throw new Error("Depósito MZN deve ser confirmado pelo PAY.co.mz.")
}
async function registerUsdt(b){
 const h=String(b.tx_hash||b.txHash||b.blockchain_tx_hash||"").trim();
 if(!/^[a-f\d]{64}$/i.test(h))throw new Error("TX hash TRON inválida.");
 const r=String(b.reference||"").trim()||ref("USDT-DEPOSIT");
 const o=await sql`SELECT * FROM transactions WHERE blockchain_tx_hash=${h} OR reference=${r} LIMIT 1`;
 if(o.length)return{success:true,existing:true,transaction:o[0]};
 const t=await sql`INSERT INTO transactions(user_id,type,asset,amount,status,reference,blockchain_tx_hash,created_at)
 VALUES(NULL,'DEPOSIT_USDT','USDT',0,'PENDING',${r},${h},NOW()) RETURNING *`;
 return{success:true,confirmed:false,reference:r,transaction:t[0]}
}
async function confirmUsdt(b){
 const r=String(b.reference||"").trim(),h=String(b.tx_hash||b.txHash||"").trim();
 const x=r?await sql`SELECT * FROM transactions WHERE reference=${r} AND type='DEPOSIT_USDT'
 ORDER BY id DESC LIMIT 1`:[];
 const t=x[0]||null,hash=h||String(t?.blockchain_tx_hash||"");
 const v=await verify(hash);
 if(t?.status==="COMPLETED")return{success:true,confirmed:true,alreadyCompleted:true,blockchain:v,transaction:t};
 if(!t){
  const d=await sql`SELECT * FROM transactions WHERE blockchain_tx_hash=${hash} LIMIT 1`;
  if(d.length)throw new Error("TX já utilizada.");
 }
 const q=t?await sql`UPDATE transactions SET status='COMPLETED',amount=${v.amount}
 WHERE id=${t.id} AND status='PENDING' RETURNING *`:
 await sql`INSERT INTO transactions(user_id,type,asset,amount,status,reference,blockchain_tx_hash,created_at)
 VALUES(NULL,'DEPOSIT_USDT','USDT',${v.amount},'COMPLETED',${r||ref("USDT-DEPOSIT")},${hash},NOW()) RETURNING *`;
 const row=q?.[0]||q;
 try{await walletChange("USDT",v.amount)}catch(e){throw e}
 return{success:true,confirmed:true,blockchain:v,transaction:row}
}

/* CONVERSÃO */
async function convert(b){
 const m=ri(b.amount_mzn??b.amount);if(!m||m<MIN||m>MAX)throw new Error("MZN inválido.");
 const rate=await realRate(),u=rnd(m/rate.value),bal=await balances();
 if(!u||bal.mzn<m)throw new Error("Fundo MZN insuficiente.");
 if(bal.usdt<u)throw new Error("USDT real insuficiente na tesouraria.");
 const r=String(b.reference||"").trim()||ref("CONVERSION");
 const o=await sql`SELECT * FROM transactions WHERE reference=${r} LIMIT 1`;
 if(o.length)return{success:true,existing:true,transaction:o[0]};
 const dm=await sql`UPDATE wallets SET balance=balance-${m},updated_at=NOW()
 WHERE asset='MZN' AND(user_id IS NULL OR user_id=0) AND balance>=${m} RETURNING id`;
 if(!dm.length)throw new Error("Não foi possível debitar MZN.");
 const du=await sql`UPDATE wallets SET balance=balance-${u},updated_at=NOW()
 WHERE asset='USDT' AND(user_id IS NULL OR user_id=0) AND balance>=${u} RETURNING id`;
 if(!du.length){await sql`UPDATE wallets SET balance=balance+${m} WHERE id=${dm[0].id}`;throw new Error("USDT insuficiente.")}
 try{
  const[t]=await sql`INSERT INTO transactions(user_id,type,asset,amount,status,reference,created_at)
  VALUES(NULL,'CONVERSION_MZN_USDT','USDT',${u},'COMPLETED',${r},NOW()) RETURNING *`;
  return{success:true,reference:r,input:{amountMzn:m},output:{amountUsdt:u},
  liquidity:{source:"TREASURY_TRON",executable:true,realUsdt:true},
  rate:{...rate,spread:0,spreadPercent:0},transaction:t}
 }catch(e){
  await sql`UPDATE wallets SET balance=balance+${m} WHERE id=${dm[0].id}`;
  throw e
 }
}

/* RESERVA */
async function reserve(amount,reference){
 const n1=n(amount);if(!n1)throw new Error("USDT inválido.");
 const r=String(reference||"").trim()||ref("USDT-RESERVE");
 const o=await sql`SELECT * FROM transactions WHERE reference=${r} AND type='USDT_RESERVATION' LIMIT 1`;
 if(o.length)return{success:true,existing:true,transaction:o[0]};
 const b=await balances(),q=await sql`SELECT COALESCE(SUM(amount),0) reserved
 FROM transactions WHERE type='USDT_RESERVATION' AND status='PENDING'`;
 if(b.usdt-Number(q[0].reserved||0)<n1)throw new Error("USDT disponível insuficiente.");
 const[t]=await sql`INSERT INTO transactions(user_id,type,asset,amount,status,reference,created_at)
 VALUES(NULL,'USDT_RESERVATION','USDT',${n1},'PENDING',${r},NOW()) RETURNING *`;
 return{success:true,reference:r,reserved:n1,transaction:t}
}
async function release(b){
 const r=String(b.reference||b.reservation_reference||"").trim();if(!r)throw new Error("reference obrigatória.");
 const x=await sql`SELECT * FROM transactions WHERE reference=${r} AND type='USDT_RESERVATION' LIMIT 1`;
 if(!x.length)throw new Error("Reserva não encontrada.");
 if(x[0].status!=="PENDING")return{success:true,alreadyProcessed:true,transaction:x[0]};
 const u=await sql`UPDATE transactions SET status='CANCELLED' WHERE id=${x[0].id}
 AND status='PENDING' RETURNING *`;return{success:true,released:Number(x[0].amount),transaction:u[0]||x[0]}
}

/* FUNDING */
async function funding(b){
 const a=String(b.asset||"").toUpperCase(),v=n(b.amount);
 if(!["MZN","USDT"].includes(a)||!v)throw new Error("Funding inválido.");
 const s=src(b.source||"MANUAL_APPROVED");if(!validSrc(s))throw new Error("Fonte inválida.");
 if(a==="MZN")throw new Error("Funding MZN manual bloqueado. Use PAY.co.mz.");
 const h=String(b.tx_hash||b.txHash||b.blockchain_tx_hash||"").trim();
 const x=await verify(h);if(Math.abs(x.amount-v)>0.000001)throw new Error("Valor da TX diferente.");
 const d=await sql`SELECT id FROM transactions WHERE blockchain_tx_hash=${h} LIMIT 1`;
 if(d.length)throw new Error("TX já utilizada.");
 const r=String(b.reference||"").trim()||ref("FUNDING");
 const[t]=await sql`INSERT INTO transactions(user_id,type,asset,amount,status,reference,blockchain_tx_hash,created_at)
 VALUES(NULL,'FUNDING','USDT',${x.amount},'COMPLETED',${r},${h},NOW()) RETURNING *`;
 await walletChange("USDT",x.amount);
 return{success:true,reference:r,amount:x.amount,asset:a,source:s,blockchain:x,transaction:t}
}

/* DASHBOARD */
async function dashboard(){
 const b=await balances(),a=(()=>{try{return treasury()}catch{return null}})();
 let rate;try{rate=await realRate()}catch(e){rate={error:e.message}};
 let trx=0;if(a)try{trx=Number(await tron().trx.getBalance(a))/1e6}catch{}
 const q=await sql`SELECT COALESCE(SUM(amount),0) reserved FROM transactions
 WHERE type='USDT_RESERVATION' AND status='PENDING'`;
 const reserved=Number(q[0].reserved||0),available=Math.max(0,b.usdt-reserved);
 return{success:true,treasury:{mzn:b.mzn,usdt:b.usdt,trx:rnd(trx),
 reservedUsdt:rnd(reserved),availableUsdt:rnd(available),
 state:available>0&&b.mzn>0?"LIQUIDEZ DISPONÍVEL":available>0?"USDT DISPONÍVEL":
 b.mzn>0?"MZN DISPONÍVEL":"SEM LIQUIDEZ"},
 wallet:{address:a,network:"TRON Mainnet",asset:"USDT",standard:"TRC-20",contract:CONTRACT},rate}
}
async function operations(){return{success:true,operations:await sql`
SELECT id,user_id,type,asset,amount,status,reference,provider,provider_reference,
blockchain_tx_hash,created_at FROM transactions ORDER BY id DESC LIMIT 50`}}
async function pending(){return{success:true,deposits:await sql`
SELECT id,type,asset,amount,status,reference,provider,provider_reference,
blockchain_tx_hash,created_at FROM transactions WHERE status='PENDING' ORDER BY id LIMIT 100`}}
async function sources(){
 const b=await balances(),a=(()=>{try{return treasury()}catch{return null}})();
 return{success:true,policy:{artificialSpread:false,usdtPegFallback:false,
 fixedUsdtMznRate:false,marketRateRequired:true,realLiquidityRequired:true},
 sources:[
 {id:"TREASURY_TRON",type:"USDT_TRON",name:"Tesouraria USDTMZ",configured:!!a,
 executionAvailable:!!a,address:a,balance:b.usdt},
 {id:"PAY_MPESA",type:"MPESA_BUSINESS",name:"Pay.co.mz — M-Pesa",configured:payOK(),executionAvailable:payOK(),asset:"MZN"},
 {id:"PAY_MKESH",type:"MKESH_BUSINESS",name:"Pay.co.mz — mKesh",configured:payOK(),executionAvailable:payOK(),asset:"MZN"},
 {id:"PAY_CARD",type:"CARD",name:"Pay.co.mz — Visa/Mastercard",configured:payOK(),executionAvailable:payOK(),asset:"MZN"},
 {id:"PAY_EMOLA",type:"EMOLA_BUSINESS",name:"Pay.co.mz — e-Mola",configured:false,executionAvailable:false},
 {id:"BINANCE",type:"BINANCE",name:"Binance",configured:!!process.env.BINANCE_API_KEY,executionAvailable:false},
 {id:"KOTANI",type:"KOTANI",name:"Kotani",configured:!!process.env.KOTANI_API_KEY,executionAvailable:false},
 {id:"REDPAY",type:"REDPAY",name:"RedPay",configured:!!process.env.REDPAY_API_KEY,executionAvailable:false}
 ]}
}

/* ROUTER — API06 */
export default async function handler(req,res){
 try{
  const u=new URL(req.url,"http://localhost");
  const ua=String(u.searchParams.get("action")||"").toLowerCase();
  if(ua==="pay_webhook"||req.headers["x-pay-signature"])return webhook(req,res);
  const a=auth(req);
  if(!["GET","POST"].includes(req.method))return json(res,405,{success:false,error:"Método não permitido."});
  const b=req.method==="POST"?await body(req):{},x=String(b.action||ua||"dashboard").toLowerCase();
  const A={
   rate:()=>({success:true,data:realRate()}),exchange_rate:()=>({success:true,data:realRate()}),
   fx_rate:()=>({success:true,data:realRate()}),refresh_rate:()=>({success:true,data:realRate(true)}),
   update_rate:()=>({success:true,data:realRate(true)}),dashboard,sources,liquidity_sources:sources,
   operations,recent_operations:operations,pending_deposits:pending,
   create_pay_treasury_charge:()=>createPay(b),pay_treasury_charge:()=>createPay(b),
   create_pagar_treasury_topup:()=>createPay(b),check_pay_treasury_charge:()=>payStatus(b),
   pay_treasury_status:()=>payStatus(b),check_pagar_treasury_topup:()=>payStatus(b),
   register_mzn_deposit:()=>registerMzn(b),confirm_mzn_deposit:()=>confirmMzn(b),
   register_usdt_deposit:()=>registerUsdt(b),confirm_usdt_deposit:()=>confirmUsdt(b),
   convert_mzn_to_usdt:()=>convert(b),reserve_usdt:()=>reserve(b.amount_usdt??b.amount,b.reference),
   release_reservation:()=>release(b),register_funding:()=>funding(b)
  };
  if(!A[x])return json(res,400,{success:false,error:`Ação "${x}" não reconhecida.`,admin:a.email});
  return json(res,200,await A[x]())
 }catch(e){console.error("USDTMZ API06:",e);
  const s=Number(e.statusCode||e.status||500);return json(res,s>=400&&s<600?s:500,{success:false,error:e.message||"Erro interno."})}
}
