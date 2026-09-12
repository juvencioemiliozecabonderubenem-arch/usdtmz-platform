"use strict";

/**
 * USDTMZ — Liquidity Execution Router
 *
 * Responsabilidade:
 *   1. Procurar fontes REAIS de liquidez.
 *   2. Obter cotações.
 *   3. Validar liquidez e preço.
 *   4. Escolher a melhor fonte.
 *   5. Executar UMA compra real.
 *   6. Verificar o resultado.
 *   7. Confirmar que o USDT foi realmente liquidado
 *      na carteira de tesouraria USDTMZ.
 *   8. Só depois permitir que o processador de envio
 *      transfira o USDT para a Binance.
 *
 * IMPORTANTE:
 *   Este arquivo NÃO cria USDT.
 *   Uma cotação NÃO significa que USDT foi comprado.
 *   Uma execução só pode ser considerada concluída
 *   depois de confirmação real do provider.
 *
 * Segurança:
 *   - Admin-only HTTP handler.
 *   - Nunca aceita endereço Binance vindo do cliente.
 *   - Nunca tenta outra fonte depois de uma execução incerta.
 *   - Usa idempotency key.
 *   - Não faz retry automático depois de uma execução
 *     potencialmente executada.
 *   - Não considera API key configurada como liquidez disponível.
 */

const crypto = require("crypto");

/*
 * O cálculo da taxa de mercado já existe no projeto.
 *
 * ATENÇÃO:
 * Se este arquivo for importado por admin-withdrawals.js,
 * NÃO importe admin-withdrawals.js de volta para cá,
 * pois isso pode criar dependência circular.
 *
 * Para evitar isso, o router tenta carregar a função
 * apenas quando necessário.
 */
let getRealUsdtMznRate = null;

function loadRateProvider() {
  if (getRealUsdtMznRate) return getRealUsdtMznRate;

  try {
    const mod = require("./admin-withdrawals.js");

    if (typeof mod.getRealUsdtMznRate !== "function") {
      throw new Error(
        "getRealUsdtMznRate não está exportada por admin-withdrawals.js"
      );
    }

    getRealUsdtMznRate = mod.getRealUsdtMznRate;

    return getRealUsdtMznRate;
  } catch (err) {
    throw new Error(
      `Não foi possível carregar o motor de taxa de mercado: ${err.message}`
    );
  }
}

/*
 * Processador que envia o USDT REAL da tesouraria para Binance.
 */
let processAdminPurchaseToBinanceInternal = null;

function loadBinanceTransferProcessor() {
  if (processAdminPurchaseToBinanceInternal) {
    return processAdminPurchaseToBinanceInternal;
  }

  try {
    const mod = require("./admin-withdrawal-process.js");

    if (
      typeof mod.processAdminPurchaseToBinanceInternal !== "function"
    ) {
      throw new Error(
        "processAdminPurchaseToBinanceInternal não está exportada por admin-withdrawal-process.js"
      );
    }

    processAdminPurchaseToBinanceInternal =
      mod.processAdminPurchaseToBinanceInternal;

    return processAdminPurchaseToBinanceInternal;
  } catch (err) {
    throw new Error(
      `Não foi possível carregar o processador Binance: ${err.message}`
    );
  }
}

/* =========================================================
 * CONFIGURAÇÃO
 * =======================================================*/

const DEFAULT_MAX_MZN = 40000;
const DEFAULT_MIN_MZN = 64;

const DEFAULT_MAX_QUOTE_AGE_MS = 15000;
const DEFAULT_HTTP_TIMEOUT_MS = 15000;

const DEFAULT_MAX_SLIPPAGE_PERCENT = 1.5;

/*
 * Por segurança, o router NÃO permite automaticamente
 * uma taxa pior que esta em relação à taxa de mercado.
 *
 * Exemplo:
 *
 * marketRate = 63
 * maxSlippage = 1.5%
 *
 * máximo aceitável ≈ 63.945 MZN/USDT
 */
function envNumber(name, fallback) {
  const raw = process.env[name];

  if (raw === undefined || raw === null || raw === "") {
    return fallback;
  }

  const value = Number(raw);

  if (!Number.isFinite(value) || value <= 0) {
    return fallback;
  }

  return value;
}

const CONFIG = Object.freeze({
  minMzn: envNumber("USDTMZ_MIN_ADMIN_BUY_MZN", DEFAULT_MIN_MZN),

  maxMzn: envNumber(
    "USDTMZ_MAX_ADMIN_BUY_MZN",
    DEFAULT_MAX_MZN
  ),

  maxQuoteAgeMs: envNumber(
    "USDTMZ_LIQUIDITY_QUOTE_MAX_AGE_MS",
    DEFAULT_MAX_QUOTE_AGE_MS
  ),

  httpTimeoutMs: envNumber(
    "USDTMZ_LIQUIDITY_HTTP_TIMEOUT_MS",
    DEFAULT_HTTP_TIMEOUT_MS
  ),

  maxSlippagePercent: envNumber(
    "USDTMZ_MAX_LIQUIDITY_SLIPPAGE_PERCENT",
    DEFAULT_MAX_SLIPPAGE_PERCENT
  ),

  treasuryAddress:
    process.env.USDTMZ_TRON_WALLET_ADDRESS || "",

  binanceDestination:
    process.env.BINANCE_USDT_TRON_ADDRESS || "",

  /*
   * Para impedir que alguém use o router como uma API
   * pública, o handler exige a sessão administrativa.
   */
  adminCookieName:
    process.env.USDTMZ_ADMIN_COOKIE_NAME ||
    "usdtmz_admin_session",

  adminSessionSecret:
    process.env.ADMIN_SESSION_SECRET || "",

  /*
   * Se TRUE, o router pode chamar automaticamente
   * o processador que envia USDT para Binance.
   *
   * Recomendação inicial:
   * false até a liquidez real estar validada em produção.
   */
  autoSendToBinance:
    String(
      process.env.USDTMZ_AUTO_SEND_TO_BINANCE || "false"
    ).toLowerCase() === "true",
});

/* =========================================================
 * ESTADOS
 * =======================================================*/

const ROUTER_STATUS = Object.freeze({
  CREATED: "CREATED",

  QUOTE_REQUESTED: "QUOTE_REQUESTED",
  QUOTED: "QUOTED",

  EXECUTING: "EXECUTING",

  ACQUIRED: "ACQUIRED",

  SETTLEMENT_PENDING: "SETTLEMENT_PENDING",
  READY_TO_SEND: "READY_TO_SEND",

  SENT_TO_BINANCE: "SENT_TO_BINANCE",
  COMPLETED: "COMPLETED",

  LIQUIDITY_REQUIRED: "LIQUIDITY_REQUIRED",

  RECONCILIATION_REQUIRED: "RECONCILIATION_REQUIRED",

  FAILED: "FAILED",
});

/* =========================================================
 * ERROS
 * =======================================================*/

class LiquidityRouterError extends Error {
  constructor(message, code, details = {}) {
    super(message);

    this.name = "LiquidityRouterError";
    this.code = code;
    this.details = details;
  }
}

class DefinitiveLiquidityError extends LiquidityRouterError {
  constructor(message, details = {}) {
    super(
      message,
      "DEFINITIVE_LIQUIDITY_FAILURE",
      details
    );

    this.name = "DefinitiveLiquidityError";
  }
}

class UncertainExecutionError extends LiquidityRouterError {
  constructor(message, details = {}) {
    super(
      message,
      "UNCERTAIN_EXECUTION",
      details
    );

    this.name = "UncertainExecutionError";
  }
}

/* =========================================================
 * HELPERS
 * =======================================================*/

function now() {
  return Date.now();
}

function isoNow() {
  return new Date().toISOString();
}

function makeId(prefix = "liq") {
  return `${prefix}_${crypto.randomUUID()}`;
}

function makeIdempotencyKey(orderId) {
  return `usdtmz-liquidity-${String(orderId)}`;
}

function isPositiveNumber(value) {
  return (
    typeof value === "number" &&
    Number.isFinite(value) &&
    value > 0
  );
}

function round(value, decimals = 8) {
  const factor = 10 ** decimals;

  return Math.round(value * factor) / factor;
}

function safeNumber(value) {
  const n = Number(value);

  return Number.isFinite(n) ? n : null;
}

function normalizeAmount(value, decimals = 8) {
  const n = Number(value);

  if (!Number.isFinite(n) || n <= 0) {
    return null;
  }

  return round(n, decimals);
}

function assertMznAmount(amountMzn) {
  const amount = Number(amountMzn);

  if (!Number.isFinite(amount)) {
    throw new LiquidityRouterError(
      "amountMZN inválido.",
      "INVALID_MZN_AMOUNT"
    );
  }

  if (amount < CONFIG.minMzn) {
    throw new LiquidityRouterError(
      `Valor mínimo: ${CONFIG.minMzn} MZN.`,
      "MZN_BELOW_MINIMUM"
    );
  }

  if (amount > CONFIG.maxMzn) {
    throw new LiquidityRouterError(
      `Valor máximo: ${CONFIG.maxMzn} MZN.`,
      "MZN_ABOVE_MAXIMUM"
    );
  }

  return round(amount, 2);
}

function assertTreasuryConfigured() {
  if (!CONFIG.treasuryAddress) {
    throw new LiquidityRouterError(
      "USDTMZ_TRON_WALLET_ADDRESS não está configurado.",
      "TREASURY_ADDRESS_NOT_CONFIGURED"
    );
  }

  if (!/^T[1-9A-HJ-NP-Za-km-z]{33}$/.test(CONFIG.treasuryAddress)) {
    throw new LiquidityRouterError(
      "USDTMZ_TRON_WALLET_ADDRESS inválido.",
      "INVALID_TREASURY_ADDRESS"
    );
  }

  return CONFIG.treasuryAddress;
}

function assertBinanceDestinationConfigured() {
  if (!CONFIG.binanceDestination) {
    throw new LiquidityRouterError(
      "BINANCE_USDT_TRON_ADDRESS não está configurado.",
      "BINANCE_DESTINATION_NOT_CONFIGURED"
    );
  }

  if (
    !/^T[1-9A-HJ-NP-Za-km-z]{33}$/.test(
      CONFIG.binanceDestination
    )
  ) {
    throw new LiquidityRouterError(
      "BINANCE_USDT_TRON_ADDRESS inválido.",
      "INVALID_BINANCE_DESTINATION"
    );
  }

  return CONFIG.binanceDestination;
}

/* =========================================================
 * HTTP
 * =======================================================*/

async function fetchJson(url, options = {}) {
  const controller = new AbortController();

  const timeout = setTimeout(() => {
    controller.abort();
  }, CONFIG.httpTimeoutMs);

  try {
    const response = await fetch(url, {
      ...options,
      signal: controller.signal,
    });

    const text = await response.text();

    let body = null;

    try {
      body = text ? JSON.parse(text) : null;
    } catch {
      body = text;
    }

    if (!response.ok) {
      throw new LiquidityRouterError(
        `HTTP ${response.status} ao consultar provider.`,
        "PROVIDER_HTTP_ERROR",
        {
          status: response.status,
          body,
        }
      );
    }

    return body;
  } catch (err) {
    if (err.name === "AbortError") {
      throw new LiquidityRouterError(
        "Timeout ao consultar provider.",
        "PROVIDER_TIMEOUT"
      );
    }

    throw err;
  } finally {
    clearTimeout(timeout);
  }
}

/* =========================================================
 * ADAPTER CONTRACT
 *
 * Cada provider real deverá implementar:
 *
 *   name
 *   executionAvailable
 *   isConfigured()
 *   getQuote(input)
 *   checkLiquidity(input, quote)
 *   execute(input, quote, idempotencyKey)
 *   getExecutionStatus(executionId)
 *   getAcquiredUSDT(input, execution)
 *   getSettlement(input, execution)
 *
 * O router nunca presume que um provider é executável.
 * =======================================================*/

function validateAdapter(adapter) {
  if (!adapter || typeof adapter !== "object") {
    return false;
  }

  if (!adapter.name) {
    return false;
  }

  if (typeof adapter.isConfigured !== "function") {
    return false;
  }

  if (typeof adapter.getQuote !== "function") {
    return false;
  }

  if (typeof adapter.checkLiquidity !== "function") {
    return false;
  }

  if (typeof adapter.execute !== "function") {
    return false;
  }

  if (typeof adapter.getExecutionStatus !== "function") {
    return false;
  }

  if (typeof adapter.getAcquiredUSDT !== "function") {
    return false;
  }

  if (typeof adapter.getSettlement !== "function") {
    return false;
  }

  return true;
}

/* =========================================================
 * ADAPTER BASE
 * =======================================================*/

function unavailableAdapter(name, reason) {
  return {
    name,

    executionAvailable: false,

    isConfigured() {
      return false;
    },

    async getQuote() {
      throw new DefinitiveLiquidityError(
        `${name}: execução não disponível.`,
        {
          provider: name,
          reason,
        }
      );
    },

    async checkLiquidity() {
      return {
        available: false,
        definitive: true,
        reason,
      };
    },

    async execute() {
      throw new DefinitiveLiquidityError(
        `${name}: adapter de execução ainda não está implementado.`,
        {
          provider: name,
          reason,
        }
      );
    },

    async getExecutionStatus() {
      return {
        status: "UNAVAILABLE",
        definitive: true,
      };
    },

    async getAcquiredUSDT() {
      return {
        confirmed: false,
        amountUSDT: 0,
      };
    },

    async getSettlement() {
      return {
        settled: false,
        confirmed: false,
      };
    },
  };
}

/* =========================================================
 * BINANCE SPOT
 *
 * NÃO habilitado para MZN automaticamente.
 *
 * Binance Spot exige um par/quote asset real.
 * Não vamos assumir MZNUSDT.
 *
 * Para ativar futuramente, será necessário:
 *
 *   - definir par real;
 *   - definir asset de financiamento;
 *   - verificar saldo;
 *   - executar ordem;
 *   - verificar fills;
 *   - retirar USDT para a carteira USDTMZ;
 *
 * A API oficial suporta criação de ordens e
 * quoteOrderQty em MARKET orders. Porém isso não
 * transforma MZN em quote asset automaticamente.
 * =======================================================*/

function createBinanceSpotAdapter() {
  const apiKey = process.env.BINANCE_API_KEY || "";
  const apiSecret = process.env.BINANCE_API_SECRET || "";

  const symbol = process.env.BINANCE_LIQUIDITY_SYMBOL || "";

  const explicitlyEnabled =
    String(
      process.env.USDTMZ_ENABLE_BINANCE_SPOT_LIQUIDITY ||
        "false"
    ).toLowerCase() === "true";

  /*
   * Mesmo com API key, continua desativado se não houver
   * um símbolo de financiamento explicitamente configurado.
   *
   * Exemplo futuro:
   * BTCUSDT
   * USDCUSDT
   *
   * Mas isso ainda exigirá que o router saiba de onde vem
   * o ativo de financiamento.
   */
  const configured =
    Boolean(apiKey && apiSecret && symbol);

  return {
    name: "BINANCE_SPOT",

    executionAvailable:
      explicitlyEnabled && configured,

    isConfigured() {
      return configured;
    },

    async getQuote(input) {
      if (!explicitlyEnabled) {
        throw new DefinitiveLiquidityError(
          "Binance Spot está desativada para o Liquidity Router.",
          {
            provider: "BINANCE_SPOT",
            reason:
              "MZN não é assumido como quote asset. Configure uma rota real de financiamento."
          }
        );
      }

      if (!configured) {
        throw new DefinitiveLiquidityError(
          "Binance Spot não está configurada.",
          {
            provider: "BINANCE_SPOT"
          }
        );
      }

      /*
       * Não inventar uma cotação MZN→USDT.
       *
       * A implementação real deverá primeiro definir
       * como o MZN é convertido no ativo aceito pelo par.
       */
      throw new DefinitiveLiquidityError(
        "Binance Spot configurada, mas a rota MZN→ativo de financiamento→USDT ainda não foi implementada.",
        {
          provider: "BINANCE_SPOT",
          symbol
        }
      );
    },

    async checkLiquidity() {
      return {
        available: false,
        definitive: true,
        reason:
          "Rota real de financiamento MZN→Binance ainda não configurada."
      };
    },

    async execute() {
      throw new DefinitiveLiquidityError(
        "Execução Binance bloqueada até existir uma rota real de financiamento.",
        {
          provider: "BINANCE_SPOT"
        }
      );
    },

    async getExecutionStatus() {
      return {
        status: "BLOCKED",
        definitive: true
      };
    },

    async getAcquiredUSDT() {
      return {
        confirmed: false,
        amountUSDT: 0
      };
    },

    async getSettlement() {
      return {
        settled: false,
        confirmed: false
      };
    }
  };
}

/* =========================================================
 * COINBASE
 *
 * Também permanece bloqueada até existir rota real
 * de financiamento em MZN.
 *
 * Coinbase Advanced Trade suporta criação de ordens,
 * consulta de ordens e fills, mas isso não significa
 * que uma conta possa comprar USDT diretamente com MZN.
 * =======================================================*/

function createCoinbaseAdapter() {
  const apiKey = process.env.COINBASE_API_KEY || "";
  const apiSecret =
    process.env.COINBASE_API_SECRET || "";

  const product =
    process.env.COINBASE_LIQUIDITY_PRODUCT || "";

  const explicitlyEnabled =
    String(
      process.env.USDTMZ_ENABLE_COINBASE_LIQUIDITY ||
        "false"
    ).toLowerCase() === "true";

  const configured =
    Boolean(apiKey && apiSecret && product);

  return {
    name: "COINBASE_ADVANCED_TRADE",

    executionAvailable:
      explicitlyEnabled && configured,

    isConfigured() {
      return configured;
    },

    async getQuote() {
      throw new DefinitiveLiquidityError(
        "Coinbase não está habilitada para MZN→USDT até existir uma rota real de financiamento.",
        {
          provider: "COINBASE_ADVANCED_TRADE",
          product
        }
      );
    },

    async checkLiquidity() {
      return {
        available: false,
        definitive: true,
        reason:
          "Rota MZN→Coinbase→USDT ainda não configurada."
      };
    },

    async execute() {
      throw new DefinitiveLiquidityError(
        "Execução Coinbase bloqueada até existir rota real de financiamento.",
        {
          provider: "COINBASE_ADVANCED_TRADE"
        }
      );
    },

    async getExecutionStatus() {
      return {
        status: "BLOCKED",
        definitive: true
      };
    },

    async getAcquiredUSDT() {
      return {
        confirmed: false,
        amountUSDT: 0
      };
    },

    async getSettlement() {
      return {
        settled: false,
        confirmed: false
      };
    }
  };
}

/* =========================================================
 * KOTANI
 * =======================================================*/

function createKotaniAdapter() {
  const apiKey =
    process.env.KOTANI_API_KEY || "";

  const explicitlyEnabled =
    String(
      process.env.USDTMZ_ENABLE_KOTANI_LIQUIDITY ||
        "false"
    ).toLowerCase() === "true";

  return unavailableAdapter(
    "KOTANI",
    apiKey && explicitlyEnabled
      ? "Credencial encontrada, mas o contrato MZN→USDT executável ainda precisa ser ligado ao adapter."
      : "Adapter de execução Kotani ainda não configurado."
  );
}

/* =========================================================
 * REDPAY
 * =======================================================*/

function createRedPayAdapter() {
  const apiKey =
    process.env.REDPAY_API_KEY || "";

  const explicitlyEnabled =
    String(
      process.env.USDTMZ_ENABLE_REDPAY_LIQUIDITY ||
        "false"
    ).toLowerCase() === "true";

  return unavailableAdapter(
    "REDPAY",
    apiKey && explicitlyEnabled
      ? "Credencial encontrada, mas o contrato real de execução ainda não está ligado ao adapter."
      : "Adapter de execução RedPay ainda não configurado."
  );
}

/* =========================================================
 * REGISTRO PADRÃO
 * =======================================================*/

function getDefaultAdapters() {
  return [
    createBinanceSpotAdapter(),
    createCoinbaseAdapter(),
    createKotaniAdapter(),
    createRedPayAdapter(),
  ].filter(validateAdapter);
}

/* =========================================================
 * NORMALIZAÇÃO DE QUOTE
 * =======================================================*/

function normalizeQuote(provider, input, rawQuote) {
  if (!rawQuote || typeof rawQuote !== "object") {
    throw new DefinitiveLiquidityError(
      `${provider}: provider não retornou uma cotação válida.`,
      {
        provider
      }
    );
  }

  const estimatedUsdt =
    safeNumber(
      rawQuote.estimatedUSDT ??
        rawQuote.usdtAmount ??
        rawQuote.amountUSDT
    );

  const effectiveRate =
    safeNumber(
      rawQuote.effectiveRate ??
        rawQuote.rate ??
        rawQuote.mznPerUSDT
    );

  if (
    !estimatedUsdt ||
    estimatedUsdt <= 0
  ) {
    throw new DefinitiveLiquidityError(
      `${provider}: quantidade USDT inválida na cotação.`,
      {
        provider,
        rawQuote
      }
    );
  }

  if (
    !effectiveRate ||
    effectiveRate <= 0
  ) {
    throw new DefinitiveLiquidityError(
      `${provider}: taxa efetiva inválida na cotação.`,
      {
        provider,
        rawQuote
      }
    );
  }

  const createdAt =
    rawQuote.createdAt
      ? new Date(rawQuote.createdAt).getTime()
      : now();

  const expiresAt =
    rawQuote.expiresAt
      ? new Date(rawQuote.expiresAt).getTime()
      : createdAt + CONFIG.maxQuoteAgeMs;

  if (!Number.isFinite(createdAt)) {
    throw new DefinitiveLiquidityError(
      `${provider}: createdAt inválido.`,
      {
        provider
      }
    );
  }

  if (!Number.isFinite(expiresAt)) {
    throw new DefinitiveLiquidityError(
      `${provider}: expiresAt inválido.`,
      {
        provider
      }
    );
  }

  return {
    provider,

    quoteId:
      rawQuote.quoteId ||
      rawQuote.id ||
      makeId("quote"),

    amountMZN: input.amountMZN,

    estimatedUSDT: round(
      estimatedUsdt,
      8
    ),

    effectiveRate: round(
      effectiveRate,
      8
    ),

    feesMZN: round(
      safeNumber(rawQuote.feesMZN) || 0,
      8
    ),

    paymentAsset:
      rawQuote.paymentAsset ||
      "MZN",

    settlementAsset:
      rawQuote.settlementAsset ||
      "USDT",

    settlementAddress:
      rawQuote.settlementAddress ||
      CONFIG.treasuryAddress,

    createdAt:
      new Date(createdAt).toISOString(),

    expiresAt:
      new Date(expiresAt).toISOString(),

    raw: rawQuote
  };
}

/* =========================================================
 * RATE / SLIPPAGE
 * =======================================================*/

async function getMarketRate() {
  const fn = loadRateProvider();

  const result = await fn(false);

  const rate =
    safeNumber(
      result?.rate ??
        result?.marketRate ??
        result?.value
    );

  if (!rate || rate <= 0) {
    throw new LiquidityRouterError(
      "Taxa de mercado inválida.",
      "INVALID_MARKET_RATE"
    );
  }

  return {
    rate,

    source:
      result?.source ||
      "market-rate-engine",

    fetchedAt:
      result?.fetchedAt ||
      isoNow(),

    raw: result
  };
}

function getMaximumAcceptableRate(marketRate) {
  return round(
    marketRate *
      (1 + CONFIG.maxSlippagePercent / 100),
    8
  );
}

function validateQuoteAgainstMarket(
  quote,
  marketRate
) {
  const maxRate =
    getMaximumAcceptableRate(marketRate);

  if (quote.effectiveRate > maxRate) {
    return {
      acceptable: false,

      reason:
        "A cotação está acima do limite máximo de slippage.",

      marketRate,

      quoteRate:
        quote.effectiveRate,

      maxRate
    };
  }

  return {
    acceptable: true,

    marketRate,

    quoteRate:
      quote.effectiveRate,

    maxRate
  };
}

/* =========================================================
 * INPUT
 * =======================================================*/

function normalizeInput(input = {}) {
  const amountMZN = assertMznAmount(
    input.amountMZN ??
      input.amountMzn ??
      input.mzn
  );

  const orderId =
    input.orderId ||
    input.purchaseOrderId ||
    input.purchase_order_id;

  if (!orderId) {
    throw new LiquidityRouterError(
      "orderId é obrigatório.",
      "ORDER_ID_REQUIRED"
    );
  }

  assertTreasuryConfigured();

  return {
    orderId: String(orderId),

    amountMZN,

    requestedUSDT:
      normalizeAmount(
        input.requestedUSDT ??
          input.usdtAmount,
        8
      ),

    treasuryAddress:
      CONFIG.treasuryAddress,

    binanceDestination:
      CONFIG.binanceDestination || null,

    maxRate:
      safeNumber(input.maxRate) || null,

    maxSlippagePercent:
      safeNumber(
        input.maxSlippagePercent
      ) ??
      CONFIG.maxSlippagePercent,

    metadata:
      input.metadata &&
      typeof input.metadata === "object"
        ? input.metadata
        : {}
  };
}

/* =========================================================
 * DISCOVERY
 * =======================================================*/

async function discoverSources(
  input,
  adapters
) {
  const results = [];

  for (const adapter of adapters) {
    let configured = false;

    try {
      configured =
        Boolean(
          await adapter.isConfigured(input)
        );
    } catch (err) {
      results.push({
        provider: adapter.name,
        configured: false,
        executionAvailable: false,
        available: false,
        error: err.message
      });

      continue;
    }

    if (!configured) {
      results.push({
        provider: adapter.name,
        configured: false,
        executionAvailable:
          Boolean(adapter.executionAvailable),
        available: false,
        reason:
          "Provider não configurado."
      });

      continue;
    }

    if (!adapter.executionAvailable) {
      results.push({
        provider: adapter.name,
        configured: true,
        executionAvailable: false,
        available: false,
        reason:
          "Provider configurado, mas execução está desabilitada."
      });

      continue;
    }

    results.push({
      provider: adapter.name,
      configured: true,
      executionAvailable: true,
      available: null
    });
  }

  return results;
}

/* =========================================================
 * QUOTATION
 * =======================================================*/

async function getQuotes(
  input,
  adapters,
  marketRate
) {
  const quotes = [];
  const rejected = [];

  for (const adapter of adapters) {
    if (!adapter.executionAvailable) {
      continue;
    }

    let configured = false;

    try {
      configured =
        Boolean(
          await adapter.isConfigured(input)
        );
    } catch (err) {
      rejected.push({
        provider: adapter.name,
        stage: "configuration",
        reason: err.message
      });

      continue;
    }

    if (!configured) {
      continue;
    }

    let rawQuote;

    try {
      rawQuote =
        await adapter.getQuote({
          ...input,
          marketRate
        });
    } catch (err) {
      rejected.push({
        provider: adapter.name,
        stage: "quote",
        reason: err.message,
        code: err.code || null
      });

      continue;
    }

    let quote;

    try {
      quote = normalizeQuote(
        adapter.name,
        input,
        rawQuote
      );
    } catch (err) {
      rejected.push({
        provider: adapter.name,
        stage: "quote_validation",
        reason: err.message,
        code: err.code || null
      });

      continue;
    }

    const marketValidation =
      validateQuoteAgainstMarket(
        quote,
        marketRate
      );

    if (!marketValidation.acceptable) {
      rejected.push({
        provider: adapter.name,
        stage: "price",
        ...marketValidation
      });

      continue;
    }

    if (
      input.maxRate &&
      quote.effectiveRate > input.maxRate
    ) {
      rejected.push({
        provider: adapter.name,
        stage: "max_rate",
        quoteRate:
          quote.effectiveRate,
        maxRate:
          input.maxRate
      });

      continue;
    }

    const age =
      now() -
      new Date(quote.createdAt).getTime();

    const expiresAt =
      new Date(quote.expiresAt).getTime();

    if (
      age > CONFIG.maxQuoteAgeMs ||
      now() >= expiresAt
    ) {
      rejected.push({
        provider: adapter.name,
        stage: "quote_expired"
      });

      continue;
    }

    quotes.push({
      adapter,
      quote,
      marketValidation
    });
  }

  /*
   * Menor MZN/USDT = melhor preço para comprar USDT.
   */
  quotes.sort(
    (a, b) =>
      a.quote.effectiveRate -
      b.quote.effectiveRate
  );

  return {
    quotes,
    rejected
  };
}

/* =========================================================
 * LIQUIDITY CHECK
 * =======================================================*/

async function checkProviderLiquidity(
  adapter,
  input,
  quote
) {
  let result;

  try {
    result =
      await adapter.checkLiquidity(
        input,
        quote
      );
  } catch (err) {
    /*
     * Falha no check não significa necessariamente
     * que o provider não tem dinheiro.
     *
     * Portanto, é tratado como falha definitiva
     * somente se o adapter declarar definitive=true.
     */
    if (err.definitive === true) {
      return {
        available: false,
        definitive: true,
        reason: err.message
      };
    }

    return {
      available: false,
      definitive: false,
      reason: err.message
    };
  }

  if (!result || typeof result !== "object") {
    return {
      available: false,
      definitive: false,
      reason:
        "Provider não retornou resultado de liquidez."
    };
  }

  return {
    available:
      result.available === true,

    definitive:
      result.definitive === true,

    reason:
      result.reason || null,

    availableUSDT:
      safeNumber(
        result.availableUSDT
      ),

    availablePaymentAsset:
      safeNumber(
        result.availablePaymentAsset
      ),

    raw: result
  };
}

/* =========================================================
 * EXECUTION RESULT
 * =======================================================*/

function normalizeExecution(
  provider,
  execution
) {
  if (
    !execution ||
    typeof execution !== "object"
  ) {
    throw new UncertainExecutionError(
      `${provider}: resposta de execução inválida.`,
      {
        provider
      }
    );
  }

  const executionId =
    execution.executionId ||
    execution.orderId ||
    execution.id;

  if (!executionId) {
    throw new UncertainExecutionError(
      `${provider}: execução retornou sem executionId.`,
      {
        provider,
        execution
      }
    );
  }

  return {
    provider,

    executionId:
      String(executionId),

    status:
      execution.status ||
      "UNKNOWN",

    submitted:
      execution.submitted !== false,

    definitive:
      execution.definitive === true,

    raw:
      execution
  };
}

/* =========================================================
 * VERIFY EXECUTION
 * =======================================================*/

async function verifyExecution(
  adapter,
  input,
  execution
) {
  let status;

  try {
    status =
      await adapter.getExecutionStatus(
        input,
        execution
      );
  } catch (err) {
    throw new UncertainExecutionError(
      `${adapter.name}: não foi possível verificar a execução.`,
      {
        provider: adapter.name,
        executionId:
          execution.executionId,
        cause: err.message
      }
    );
  }

  if (!status || typeof status !== "object") {
    throw new UncertainExecutionError(
      `${adapter.name}: status de execução inválido.`,
      {
        provider: adapter.name,
        executionId:
          execution.executionId
      }
    );
  }

  const normalizedStatus =
    String(
      status.status || ""
    ).toUpperCase();

  /*
   * Estados definitivamente falhados.
   */
  if (
    [
      "FAILED",
      "REJECTED",
      "CANCELED",
      "CANCELLED",
      "EXPIRED"
    ].includes(normalizedStatus)
  ) {
    throw new DefinitiveLiquidityError(
      `${adapter.name}: execução não foi concluída.`,
      {
        provider: adapter.name,
        executionId:
          execution.executionId,
        status: normalizedStatus
      }
    );
  }

  /*
   * Estados ainda incertos/em andamento.
   */
  if (
    [
      "",
      "UNKNOWN",
      "PENDING",
      "OPEN",
      "PROCESSING",
      "NEW",
      "PARTIALLY_FILLED"
    ].includes(normalizedStatus)
  ) {
    throw new UncertainExecutionError(
      `${adapter.name}: execução ainda não está definitivamente concluída.`,
      {
        provider: adapter.name,
        executionId:
          execution.executionId,
        status: normalizedStatus
      }
    );
  }

  return status;
}

/* =========================================================
 * VERIFY ACQUIRED USDT
 * =======================================================*/

async function verifyAcquiredUSDT(
  adapter,
  input,
  execution
) {
  let acquired;

  try {
    acquired =
      await adapter.getAcquiredUSDT(
        input,
        execution
      );
  } catch (err) {
    throw new UncertainExecutionError(
      `${adapter.name}: não foi possível verificar USDT adquirido.`,
      {
        provider: adapter.name,
        executionId:
          execution.executionId,
        cause: err.message
      }
    );
  }

  if (
    !acquired ||
    acquired.confirmed !== true
  ) {
    throw new UncertainExecutionError(
      `${adapter.name}: USDT adquirido não foi confirmado.`,
      {
        provider: adapter.name,
        executionId:
          execution.executionId,
        acquired
      }
    );
  }

  const amountUSDT =
    safeNumber(
      acquired.amountUSDT
    );

  if (
    !amountUSDT ||
    amountUSDT <= 0
  ) {
    throw new UncertainExecutionError(
      `${adapter.name}: quantidade USDT adquirida inválida.`,
      {
        provider: adapter.name,
        executionId:
          execution.executionId,
        acquired
      }
    );
  }

  return {
    ...acquired,

    amountUSDT:
      round(amountUSDT, 8)
  };
}

/* =========================================================
 * VERIFY SETTLEMENT
 * =======================================================*/

async function verifySettlement(
  adapter,
  input,
  execution,
  acquired
) {
  let settlement;

  try {
    settlement =
      await adapter.getSettlement(
        input,
        execution,
        acquired
      );
  } catch (err) {
    throw new UncertainExecutionError(
      `${adapter.name}: não foi possível confirmar settlement.`,
      {
        provider: adapter.name,
        executionId:
          execution.executionId,
        cause: err.message
      }
    );
  }

  if (
    !settlement ||
    settlement.confirmed !== true ||
    settlement.settled !== true
  ) {
    throw new UncertainExecutionError(
      `${adapter.name}: USDT ainda não foi confirmado na tesouraria.`,
      {
        provider: adapter.name,
        executionId:
          execution.executionId,
        settlement
      }
    );
  }

  /*
   * O settlement deve chegar à carteira USDTMZ.
   * Nunca aceitar automaticamente outro endereço.
   */
  if (
    settlement.address &&
    settlement.address !==
      input.treasuryAddress
  ) {
    throw new LiquidityRouterError(
      "USDT foi liquidado em endereço diferente da tesouraria USDTMZ.",
      "WRONG_SETTLEMENT_ADDRESS",
      {
        expected:
          input.treasuryAddress,
        received:
          settlement.address,
        provider:
          adapter.name,
        executionId:
          execution.executionId
      }
    );
  }

  return settlement;
}

/* =========================================================
 * MAIN ROUTER
 * =======================================================*/

async function executeLiquidityPurchase(
  rawInput,
  options = {}
) {
  const input =
    normalizeInput(rawInput);

  const adapters =
    Array.isArray(options.adapters)
      ? options.adapters.filter(
          validateAdapter
        )
      : getDefaultAdapters();

  if (!adapters.length) {
    return {
      ok: false,

      status:
        ROUTER_STATUS.LIQUIDITY_REQUIRED,

      code:
        "NO_LIQUIDITY_ADAPTERS",

      orderId:
        input.orderId,

      message:
        "Nenhum adapter de liquidez disponível."
    };
  }

  /*
   * Uma idempotency key por orderId.
   *
   * O mesmo orderId nunca deve iniciar duas compras
   * externas simultâneas.
   */
  const idempotencyKey =
    makeIdempotencyKey(
      input.orderId
    );

  /*
   * Taxa de mercado somente para comparação.
   * Não é usada como prova de execução.
   */
  const market =
    await getMarketRate();

  const marketRate =
    market.rate;

  const marketMaxRate =
    input.maxRate ||
    getMaximumAcceptableRate(
      marketRate
    );

  /*
   * Obter quotes.
   */
  const quoteResult =
    await getQuotes(
      {
        ...input,
        maxRate:
          marketMaxRate
      },
      adapters,
      marketRate
    );

  if (!quoteResult.quotes.length) {
    return {
      ok: false,

      status:
        ROUTER_STATUS.LIQUIDITY_REQUIRED,

      code:
        "NO_EXECUTABLE_LIQUIDITY",

      orderId:
        input.orderId,

      amountMZN:
        input.amountMZN,

      marketRate,

      maxAcceptableRate:
        marketMaxRate,

      rejected:
        quoteResult.rejected
    };
  }

  /*
   * Tentar os providers pela melhor cotação.
   */
  for (
    let index = 0;
    index < quoteResult.quotes.length;
    index++
  ) {
    const candidate =
      quoteResult.quotes[index];

    const adapter =
      candidate.adapter;

    const quote =
      candidate.quote;

    /*
     * Revalidar que a quote ainda está fresca.
     */
    const expiresAt =
      new Date(
        quote.expiresAt
      ).getTime();

    if (
      !Number.isFinite(expiresAt) ||
      now() >= expiresAt
    ) {
      continue;
    }

    /*
     * Confirmar liquidez imediatamente antes
     * da execução.
     */
    const liquidity =
      await checkProviderLiquidity(
        adapter,
        input,
        quote
      );

    if (!liquidity.available) {
      /*
       * Falta definitiva de liquidez:
       * podemos tentar outro provider.
       */
      if (liquidity.definitive) {
        continue;
      }

      /*
       * Se o provider não consegue dizer se há
       * liquidez, não devemos executar cegamente.
       *
       * Passamos ao próximo provider.
       */
      continue;
    }

    /*
     * EXECUÇÃO REAL
     */
    let rawExecution;

    try {
      rawExecution =
        await adapter.execute(
          input,
          quote,
          idempotencyKey
        );
    } catch (err) {
      /*
       * MUITO IMPORTANTE:
       *
       * Se não sabemos se o provider recebeu/executou
       * a ordem, NÃO tentamos outro provider.
       *
       * Isso evita comprar duas vezes.
       */
      if (
        err instanceof
          DefinitiveLiquidityError ||
        err.code ===
          "DEFINITIVE_LIQUIDITY_FAILURE"
      ) {
        continue;
      }

      throw new UncertainExecutionError(
        `${adapter.name}: erro durante execução; estado precisa de reconciliação.`,
        {
          provider:
            adapter.name,
          orderId:
            input.orderId,
          cause:
            err.message
        }
      );
    }

    let execution;

    try {
      execution =
        normalizeExecution(
          adapter.name,
          rawExecution
        );
    } catch (err) {
      /*
       * Se o provider aceitou algo mas não deu
       * executionId, não podemos tentar outro.
       */
      throw err;
    }

    /*
     * Verificar execução real.
     */
    let executionStatus;

    try {
      executionStatus =
        await verifyExecution(
          adapter,
          input,
          execution
        );
    } catch (err) {
      /*
       * Uma execução que pode ter ocorrido
       * não deve gerar nova compra.
       */
      if (
        err instanceof
        DefinitiveLiquidityError
      ) {
        continue;
      }

      throw err;
    }

    /*
     * Confirmar USDT efetivamente adquirido.
     */
    const acquired =
      await verifyAcquiredUSDT(
        adapter,
        input,
        execution
      );

    /*
     * Confirmar que o USDT chegou à tesouraria.
     */
    const settlement =
      await verifySettlement(
        adapter,
        input,
        execution,
        acquired
      );

    /*
     * Neste ponto temos:
     *
     *   execução real
     *   +
     *   USDT real adquirido
     *   +
     *   settlement confirmado
     *
     * Só agora estamos autorizados a considerar
     * a compra pronta para transferência.
     */
    const result = {
      ok: true,

      status:
        ROUTER_STATUS.READY_TO_SEND,

      orderId:
        input.orderId,

      provider:
        adapter.name,

      quote: {
        quoteId:
          quote.quoteId,

        amountMZN:
          quote.amountMZN,

        estimatedUSDT:
          quote.estimatedUSDT,

        effectiveRate:
          quote.effectiveRate,

        feesMZN:
          quote.feesMZN,

        expiresAt:
          quote.expiresAt
      },

      market: {
        rate:
          marketRate,

        source:
          market.source,

        fetchedAt:
          market.fetchedAt,

        maxAcceptableRate:
          marketMaxRate
      },

      execution: {
        executionId:
          execution.executionId,

        status:
          executionStatus.status
      },

      acquired: {
        amountUSDT:
          acquired.amountUSDT
      },

      settlement: {
        confirmed:
          settlement.confirmed,

        settled:
          settlement.settled,

        address:
          settlement.address ||
          input.treasuryAddress,

        txHash:
          settlement.txHash ||
          settlement.transactionHash ||
          null
      },

      treasuryAddress:
        input.treasuryAddress,

      binanceDestination:
        input.binanceDestination,

      idempotencyKey
    };

    /*
     * ENV opcional:
     *
     * USDTMZ_AUTO_SEND_TO_BINANCE=true
     *
     * Só é executado depois do settlement.
     */
    if (
      CONFIG.autoSendToBinance
    ) {
      assertBinanceDestinationConfigured();

      const processor =
        loadBinanceTransferProcessor();

      let transferResult;

      try {
        transferResult =
          await processor(
            input.orderId
          );
      } catch (err) {
        /*
         * O USDT já foi comprado.
         *
         * Portanto NÃO devemos executar a compra
         * novamente.
         *
         * O problema agora é somente no envio
         * da tesouraria para Binance.
         */
        return {
          ...result,

          ok: false,

          status:
            ROUTER_STATUS.READY_TO_SEND,

          code:
            "USDT_ACQUIRED_TRANSFER_PENDING",

          transferError:
            err.message,

          executionCompleted:
            true,

          acquiredUSDT:
            acquired.amountUSDT
        };
      }

      return {
        ...result,

        status:
          transferResult?.status ||
          ROUTER_STATUS.SENT_TO_BINANCE,

        transfer:
          transferResult
      };
    }

    return result;
  }

  /*
   * Nenhum provider conseguiu executar
   * definitivamente.
   */
  return {
    ok: false,

    status:
      ROUTER_STATUS.LIQUIDITY_REQUIRED,

    code:
      "ALL_LIQUIDITY_SOURCES_FAILED",

    orderId:
      input.orderId,

    amountMZN:
      input.amountMZN,

    marketRate,

    maxAcceptableRate:
      marketMaxRate,

    rejected:
      quoteResult.rejected
  };
}

/* =========================================================
 * QUOTE-ONLY
 *
 * Não compra nada.
 * Útil para o painel administrativo.
 * =======================================================*/

async function getBestLiquidityQuote(
  rawInput,
  options = {}
) {
  const input =
    normalizeInput(rawInput);

  const adapters =
    Array.isArray(options.adapters)
      ? options.adapters.filter(
          validateAdapter
        )
      : getDefaultAdapters();

  const market =
    await getMarketRate();

  const quoteResult =
    await getQuotes(
      input,
      adapters,
      market.rate
    );

  if (!quoteResult.quotes.length) {
    return {
      ok: false,

      status:
        ROUTER_STATUS.LIQUIDITY_REQUIRED,

      marketRate:
        market.rate,

      rejected:
        quoteResult.rejected
    };
  }

  const best =
    quoteResult.quotes[0];

  return {
    ok: true,

    status:
      ROUTER_STATUS.QUOTED,

    provider:
      best.adapter.name,

    quote:
      best.quote,

    market: {
      rate:
        market.rate,

      source:
        market.source,

      maxAcceptableRate:
        getMaximumAcceptableRate(
          market.rate
        )
    },

    alternatives:
      quoteResult.quotes
        .slice(1)
        .map((item) => ({
          provider:
            item.adapter.name,

          quote:
            item.quote
        })),

    rejected:
      quoteResult.rejected
  };
}

/* =========================================================
 * SOURCES
 * =======================================================*/

async function getLiquiditySources(
  options = {}
) {
  const adapters =
    Array.isArray(options.adapters)
      ? options.adapters.filter(
          validateAdapter
        )
      : getDefaultAdapters();

  const sources = [];

  for (const adapter of adapters) {
    let configured = false;

    try {
      configured =
        Boolean(
          await adapter.isConfigured()
        );
    } catch {
      configured = false;
    }

    sources.push({
      provider:
        adapter.name,

      configured,

      executionAvailable:
        Boolean(
          adapter.executionAvailable
        )
    });
  }

  return sources;
}

/* =========================================================
 * ADMIN SESSION
 * =======================================================*/

function parseCookies(header) {
  const cookies = {};

  if (!header) {
    return cookies;
  }

  const parts =
    String(header).split(";");

  for (const part of parts) {
    const index =
      part.indexOf("=");

    if (index <= 0) {
      continue;
    }

    const key =
      part
        .slice(0, index)
        .trim();

    const value =
      part
        .slice(index + 1)
        .trim();

    cookies[key] =
      decodeURIComponent(value);
  }

  return cookies;
}

function safeEqualStrings(a, b) {
  const aa =
    Buffer.from(
      String(a)
    );

  const bb =
    Buffer.from(
      String(b)
    );

  if (aa.length !== bb.length) {
    return false;
  }

  return crypto.timingSafeEqual(
    aa,
    bb
  );
}

function verifyAdminSession(req) {
  if (!CONFIG.adminSessionSecret) {
    return {
      ok: false,

      reason:
        "ADMIN_SESSION_SECRET não configurado."
    };
  }

  const cookies =
    parseCookies(
      req.headers?.cookie || ""
    );

  const token =
    cookies[
      CONFIG.adminCookieName
    ];

  if (!token) {
    return {
      ok: false,

      reason:
        "Sessão administrativa ausente."
    };
  }

  const firstDot =
    token.indexOf(".");

  if (firstDot <= 0) {
    return {
      ok: false,

      reason:
        "Sessão administrativa inválida."
    };
  }

  const payloadB64 =
    token.slice(
      0,
      firstDot
    );

  const signature =
    token.slice(
      firstDot + 1
    );

  const expected =
    crypto
      .createHmac(
        "sha256",
        CONFIG.adminSessionSecret
      )
      .update(payloadB64)
      .digest("hex");

  if (
    !safeEqualStrings(
      signature,
      expected
    )
  ) {
    return {
      ok: false,

      reason:
        "Assinatura da sessão inválida."
    };
  }

  let payload;

  try {
    payload =
      JSON.parse(
        Buffer.from(
          payloadB64,
          "base64url"
        ).toString("utf8")
      );
  } catch {
    return {
      ok: false,

      reason:
        "Payload da sessão inválido."
    };
  }

  if (
    !payload ||
    payload.id !== "admin"
  ) {
    return {
      ok: false,

      reason:
        "Sessão não pertence ao administrador."
    };
  }

  if (
    !Number.isFinite(
      Number(payload.exp)
    )
  ) {
    return {
      ok: false,

      reason:
        "Sessão sem expiração válida."
    };
  }

  if (
    Number(payload.exp) <
    Math.floor(Date.now() / 1000)
  ) {
    return {
      ok: false,

      reason:
        "Sessão administrativa expirada."
    };
  }

  return {
    ok: true,

    payload
  };
}

/* =========================================================
 * JSON BODY
 * =======================================================*/

async function readJsonBody(req) {
  if (
    req.body &&
    typeof req.body === "object"
  ) {
    return req.body;
  }

  return new Promise(
    (resolve, reject) => {
      let data = "";

      req.on(
        "data",
        (chunk) => {
          data += chunk;

          /*
           * Limite simples para impedir payload
           * administrativo gigante.
           */
          if (
            data.length >
            1024 * 1024
          ) {
            reject(
              new LiquidityRouterError(
                "Payload demasiado grande.",
                "PAYLOAD_TOO_LARGE"
              )
            );

            try {
              req.destroy();
            } catch {}
          }
        }
      );

      req.on(
        "end",
        () => {
          if (!data) {
            resolve({});
            return;
          }

          try {
            resolve(
              JSON.parse(data)
            );
          } catch {
            reject(
              new LiquidityRouterError(
                "JSON inválido.",
                "INVALID_JSON"
              )
            );
          }
        }
      );

      req.on(
        "error",
        reject
      );
    }
  );
}

/* =========================================================
 * HTTP RESPONSE
 * =======================================================*/

function sendJson(
  res,
  status,
  body
) {
  if (res.headersSent) {
    return;
  }

  res.statusCode =
    status;

  res.setHeader(
    "Content-Type",
    "application/json; charset=utf-8"
  );

  res.setHeader(
    "Cache-Control",
    "no-store"
  );

  res.end(
    JSON.stringify(body)
  );
}

/* =========================================================
 * HTTP HANDLER
 *
 * POST:
 *
 *   { action: "sources" }
 *
 *   { action: "quote", ... }
 *
 *   { action: "execute", ... }
 *
 *   { action: "send_to_binance",
 *     purchase_order_id: "..." }
 *
 * =======================================================*/

async function handler(req, res) {
  /*
   * Somente POST.
   */
  if (
    req.method !== "POST"
  ) {
    sendJson(
      res,
      405,
      {
        ok: false,
        error:
          "Método não permitido."
      }
    );

    return;
  }

  /*
   * Toda operação do router é administrativa.
   */
  const session =
    verifyAdminSession(req);

  if (!session.ok) {
    sendJson(
      res,
      401,
      {
        ok: false,
        error:
          "Não autorizado."
      }
    );

    return;
  }

  try {
    const body =
      await readJsonBody(req);

    const action =
      String(
        body.action || ""
      ).trim();

    /*
     * SOURCES
     */
    if (
      action === "sources" ||
      action === "liquidity_sources"
    ) {
      const sources =
        await getLiquiditySources();

      sendJson(
        res,
        200,
        {
          ok: true,

          sources,

          treasuryAddress:
            CONFIG.treasuryAddress,

          binanceConfigured:
            Boolean(
              CONFIG.binanceDestination
            )
        }
      );

      return;
    }

    /*
     * QUOTE
     */
    if (
      action === "quote" ||
      action === "best_quote"
    ) {
      const result =
        await getBestLiquidityQuote(
          body
        );

      sendJson(
        res,
        result.ok ? 200 : 409,
        result
      );

      return;
    }

    /*
     * EXECUTE
     */
    if (
      action === "execute" ||
      action === "buy_usdt"
    ) {
      /*
       * A chamada HTTP nunca deve aceitar
       * destination arbitrário.
       */
      delete body.destination;
      delete body.withdrawAddress;
      delete body.binanceAddress;
      delete body.to;

      const result =
        await executeLiquidityPurchase(
          body
        );

      /*
       * Liquidez inexistente:
       * 409 é melhor que 500.
       */
      if (
        result.status ===
        ROUTER_STATUS.LIQUIDITY_REQUIRED
      ) {
        sendJson(
          res,
          409,
          result
        );

        return;
      }

      /*
       * Reconciliação:
       * execução potencialmente feita.
       */
      if (
        result.status ===
        ROUTER_STATUS.RECONCILIATION_REQUIRED
      ) {
        sendJson(
          res,
          409,
          result
        );

        return;
      }

      sendJson(
        res,
        result.ok ? 200 : 409,
        result
      );

      return;
    }

    /*
     * SEND TO BINANCE
     *
     * Este action NÃO compra USDT.
     *
     * Ele apenas chama o processador que já existe,
     * depois que o USDT real está na tesouraria.
     */
    if (
      action ===
      "send_to_binance"
    ) {
      const orderId =
        body.purchase_order_id ||
        body.orderId;

      if (!orderId) {
        sendJson(
          res,
          400,
          {
            ok: false,

            error:
              "purchase_order_id é obrigatório."
          }
        );

        return;
      }

      assertBinanceDestinationConfigured();

      const processor =
        loadBinanceTransferProcessor();

      const result =
        await processor(
          String(orderId)
        );

      sendJson(
        res,
        200,
        {
          ok: true,

          status:
            result?.status ||
            ROUTER_STATUS.SENT_TO_BINANCE,

          result
        }
      );

      return;
    }

    sendJson(
      res,
      400,
      {
        ok: false,

        error:
          "Ação inválida.",

        allowedActions: [
          "sources",
          "quote",
          "execute",
          "send_to_binance"
        ]
      }
    );
  } catch (err) {
    console.error(
      "[USDTMZ][LIQUIDITY_ROUTER]",
      err
    );

    if (
      err instanceof
      UncertainExecutionError
    ) {
      sendJson(
        res,
        409,
        {
          ok: false,

          status:
            ROUTER_STATUS.RECONCILIATION_REQUIRED,

          code:
            err.code,

          error:
            err.message,

          details:
            err.details || {}
        }
      );

      return;
    }

    if (
      err instanceof
      DefinitiveLiquidityError
    ) {
      sendJson(
        res,
        409,
        {
          ok: false,

          status:
            ROUTER_STATUS.LIQUIDITY_REQUIRED,

          code:
            err.code,

          error:
            err.message,

          details:
            err.details || {}
        }
      );

      return;
    }

    if (
      err instanceof
      LiquidityRouterError
    ) {
      sendJson(
        res,
        400,
        {
          ok: false,

          code:
            err.code,

          error:
            err.message,

          details:
            err.details || {}
        }
      );

      return;
    }

    sendJson(
      res,
      500,
      {
        ok: false,

        error:
          "Erro interno do Liquidity Router."
      }
    );
  }
}

/* =========================================================
 * EXPORTS
 * =======================================================*/

module.exports = handler;

module.exports.handler =
  handler;

module.exports.executeLiquidityPurchase =
  executeLiquidityPurchase;

module.exports.getBestLiquidityQuote =
  getBestLiquidityQuote;

module.exports.getLiquiditySources =
  getLiquiditySources;

module.exports.ROUTER_STATUS =
  ROUTER_STATUS;

module.exports.LiquidityRouterError =
  LiquidityRouterError;

module.exports.DefinitiveLiquidityError =
  DefinitiveLiquidityError;

module.exports.UncertainExecutionError =
  UncertainExecutionError;

/*
 * Permite registrar adapters reais posteriormente
 * sem alterar a lógica central do router.
 */
module.exports.validateAdapter =
  validateAdapter;

module.exports.makeIdempotencyKey =
  makeIdempotencyKey;
