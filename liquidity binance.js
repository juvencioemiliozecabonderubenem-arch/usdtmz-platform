"use strict";

/**
 * USDTMZ — Binance Connect / On-Ramp Liquidity Adapter
 *
 * ROTA:
 *
 *     MZN
 *      ↓
 * Binance Connect / On-Ramp
 *      ↓
 * USDT
 *      ↓
 * carteira TRON da USDTMZ
 *
 * IMPORTANTE:
 *
 * Este adapter NÃO usa Binance Spot para fingir
 * que MZN é um quote asset.
 *
 * Ele usa a família Binance Connect / On-Ramp,
 * que possui APIs específicas para fiat → crypto.
 *
 * A operação só será considerada disponível se:
 *
 *   1. Binance aceitar MZN;
 *   2. Binance disponibilizar método de pagamento;
 *   3. Binance fornecer quote;
 *   4. quote estiver válido;
 *   5. execução for aceita;
 *   6. execução puder ser verificada;
 *   7. USDT puder ser liquidado na carteira USDTMZ.
 *
 * NUNCA:
 *
 *   quote = compra concluída
 *
 * A quote é somente uma cotação.
 */

/* =========================================================
 * CONFIG
 * ======================================================= */

const BASE_URL =
  process.env.BINANCE_CONNECT_BASE_URL ||
  "https://papi.binance.com";

const API_KEY =
  process.env.BINANCE_CONNECT_API_KEY ||
  process.env.BINANCE_API_KEY ||
  "";

const API_SECRET =
  process.env.BINANCE_CONNECT_API_SECRET ||
  process.env.BINANCE_API_SECRET ||
  "";

const FIAT_CURRENCY =
  (
    process.env.BINANCE_CONNECT_FIAT_CURRENCY ||
    "MZN"
  ).toUpperCase();

const CRYPTO_CURRENCY =
  (
    process.env.BINANCE_CONNECT_CRYPTO_CURRENCY ||
    "USDT"
  ).toUpperCase();

const NETWORK =
  (
    process.env.BINANCE_CONNECT_NETWORK ||
    "TRON"
  ).toUpperCase();

const TREASURY_ADDRESS =
  process.env.USDTMZ_TRON_WALLET_ADDRESS ||
  "";

const EXPLICITLY_ENABLED =
  String(
    process.env.USDTMZ_ENABLE_BINANCE_CONNECT ||
      "false"
  ).toLowerCase() === "true";

const REQUEST_TIMEOUT_MS =
  Number(
    process.env.BINANCE_CONNECT_TIMEOUT_MS ||
      15000
  );

/*
 * Algumas integrações Binance Connect são disponibilizadas
 * somente para parceiros/contas aprovadas.
 *
 * Portanto, a existência de API key NÃO significa
 * automaticamente que o serviço está disponível.
 */

/* =========================================================
 * ERRORS
 * ======================================================= */

class BinanceLiquidityError extends Error {
  constructor(
    message,
    code = "BINANCE_LIQUIDITY_ERROR",
    details = {}
  ) {
    super(message);

    this.name =
      "BinanceLiquidityError";

    this.code = code;

    this.details =
      details;
  }
}

class BinanceDefinitiveError
  extends BinanceLiquidityError {
  constructor(
    message,
    details = {}
  ) {
    super(
      message,
      "DEFINITIVE_LIQUIDITY_FAILURE",
      details
    );
  }
}

class BinanceUncertainError
  extends BinanceLiquidityError {
  constructor(
    message,
    details = {}
  ) {
    super(
      message,
      "UNCERTAIN_EXECUTION",
      details
    );
  }
}

/* =========================================================
 * HELPERS
 * ======================================================= */

function sleep(ms) {
  return new Promise(
    (resolve) =>
      setTimeout(resolve, ms)
  );
}

function safeNumber(value) {
  const n =
    Number(value);

  return Number.isFinite(n)
    ? n
    : null;
}

function round(
  value,
  decimals = 8
) {
  const factor =
    10 ** decimals;

  return (
    Math.round(
      Number(value) * factor
    ) / factor
  );
}

function isValidTronAddress(
  address
) {
  return /^T[1-9A-HJ-NP-Za-km-z]{33}$/.test(
    String(address || "")
  );
}

function makeIdempotencyKey(
  orderId
) {
  return `usdtmz-binance-${String(
    orderId
  )}`;
}

/* =========================================================
 * HTTP
 * ======================================================= */

async function request(
  path,
  {
    method = "POST",
    body = null,
    headers = {}
  } = {}
) {
  const controller =
    new AbortController();

  const timeout =
    setTimeout(
      () =>
        controller.abort(),
      REQUEST_TIMEOUT_MS
    );

  try {
    const url =
      `${BASE_URL}${path}`;

    const finalHeaders = {
      "Content-Type":
        "application/json",

      Accept:
        "application/json",

      ...headers
    };

    if (API_KEY) {
      /*
       * Binance Connect authentication may differ
       * depending on the Connect product/account.
       *
       * Keep the credential server-side.
       */
      finalHeaders[
        "X-MBX-APIKEY"
      ] = API_KEY;
    }

    const response =
      await fetch(
        url,
        {
          method,

          headers:
            finalHeaders,

          body:
            body === null
              ? undefined
              : JSON.stringify(body),

          signal:
            controller.signal
        }
      );

    const text =
      await response.text();

    let json;

    try {
      json =
        text
          ? JSON.parse(text)
          : null;
    } catch {
      json = {
        raw: text
      };
    }

    if (!response.ok) {
      throw new BinanceLiquidityError(
        `Binance HTTP ${response.status}.`,
        "BINANCE_HTTP_ERROR",
        {
          status:
            response.status,

          response:
            json
        }
      );
    }

    return json;
  } catch (error) {
    if (
      error?.name ===
      "AbortError"
    ) {
      throw new BinanceUncertainError(
        "Timeout ao comunicar com Binance.",
        {
          cause:
            "REQUEST_TIMEOUT"
        }
      );
    }

    throw error;
  } finally {
    clearTimeout(timeout);
  }
}

/* =========================================================
 * RESPONSE HELPERS
 * ======================================================= */

function assertBinanceSuccess(
  response,
  operation
) {
  if (!response) {
    throw new BinanceDefinitiveError(
      `Binance não retornou resposta em ${operation}.`
    );
  }

  /*
   * Algumas APIs Binance retornam:
   *
   * success: true
   *
   * code: "000000"
   *
   * Outras podem retornar HTTP 200 com estrutura
   * diferente.
   *
   * Não considerar sucesso sem dados necessários.
   */

  if (
    response.success === false
  ) {
    throw new BinanceDefinitiveError(
      `Binance rejeitou ${operation}.`,
      {
        response
      }
    );
  }

  if (
    response.code &&
    String(response.code) !==
      "000000"
  ) {
    throw new BinanceDefinitiveError(
      `Binance retornou código ${response.code} em ${operation}.`,
      {
        response
      }
    );
  }

  return response;
}

function extractData(
  response
) {
  if (
    response &&
    response.data !== undefined
  ) {
    return response.data;
  }

  return response;
}

/* =========================================================
 * FIAT SUPPORT
 *
 * Endpoint da Binance Connect para descobrir
 * moedas fiat suportadas para compra.
 *
 * O adapter NÃO assume que MZN existe.
 * ======================================================= */

async function getFiatList() {
  const response =
    await request(
      "/papi/v1/ramp/connect/buy/fiat-list",
      {
        method: "POST",

        body: {}
      }
    );

  assertBinanceSuccess(
    response,
    "fiat-list"
  );

  const data =
    extractData(response);

  return Array.isArray(data)
    ? data
    : [];
}

function normalizeFiatCode(
  item
) {
  if (!item) {
    return "";
  }

  return String(
    item.fiatCurrency ||
      item.fiat ||
      item.currency ||
      item.code ||
      ""
  ).toUpperCase();
}

async function isMznSupported() {
  const list =
    await getFiatList();

  const match =
    list.find(
      (item) =>
        normalizeFiatCode(item) ===
        FIAT_CURRENCY
    );

  return {
    supported:
      Boolean(match),

    fiat:
      match || null,

    list
  };
}

/* =========================================================
 * PAYMENT METHODS
 *
 * Binance disponibiliza uma API de métodos de pagamento
 * para cada fiat.
 * ======================================================= */

async function getPaymentMethods() {
  const response =
    await request(
      "/papi/v2/ramp/connect/buy/payment-method-list",
      {
        method: "POST",

        body: {
          language:
            process.env.BINANCE_CONNECT_LANGUAGE ||
            "en-US"
        }
      }
    );

  assertBinanceSuccess(
    response,
    "payment-method-list"
  );

  const data =
    extractData(response);

  if (
    !Array.isArray(data)
  ) {
    return [];
  }

  const fiatEntry =
    data.find(
      (item) =>
        String(
          item.fiat ||
            item.fiatCurrency ||
            ""
        ).toUpperCase() ===
        FIAT_CURRENCY
    );

  if (!fiatEntry) {
    return [];
  }

  return (
    fiatEntry.paymentMethods ||
    []
  );
}

/*
 * Seleciona o método configurado pelo administrador,
 * se houver.
 *
 * Caso não seja configurado, deixamos a Binance
 * escolher o melhor método ao gerar a cotação.
 */
function getConfiguredPaymentMethod() {
  const code =
    process.env.BINANCE_CONNECT_PAY_METHOD_CODE ||
    "";

  const subCode =
    process.env.BINANCE_CONNECT_PAY_METHOD_SUBCODE ||
    "";

  if (!code) {
    return null;
  }

  return {
    payMethodCode:
      code,

    payMethodSubCode:
      subCode || undefined
  };
}

/* =========================================================
 * CRYPTO / NETWORK VALIDATION
 * ======================================================= */

async function getCryptoNetworks() {
  const response =
    await request(
      "/papi/v1/ramp/connect/crypto-network",
      {
        method: "POST",

        body: {}
      }
    );

  assertBinanceSuccess(
    response,
    "crypto-network"
  );

  return extractData(response);
}

async function validateUSDTNetwork() {
  const networks =
    await getCryptoNetworks();

  if (
    !Array.isArray(networks)
  ) {
    throw new BinanceDefinitiveError(
      "Binance não retornou redes de crypto."
    );
  }

  const usdt =
    networks.find(
      (item) =>
        String(
          item.cryptoCurrency ||
            ""
        ).toUpperCase() ===
        CRYPTO_CURRENCY
    );

  if (!usdt) {
    throw new BinanceDefinitiveError(
      `Binance não retornou ${CRYPTO_CURRENCY} nas redes disponíveis.`
    );
  }

  const network =
    (
      usdt.networks ||
      []
    ).find(
      (item) =>
        String(
          item.network || ""
        ).toUpperCase() ===
        NETWORK
    );

  if (!network) {
    throw new BinanceDefinitiveError(
      `${CRYPTO_CURRENCY} não está disponível na rede ${NETWORK} através desta integração Binance.`
    );
  }

  if (
    network.withdrawEnable === false
  ) {
    throw new BinanceDefinitiveError(
      `Retirada de ${CRYPTO_CURRENCY} pela rede ${NETWORK} está desativada na Binance.`
    );
  }

  return network;
}

/* =========================================================
 * QUOTE
 *
 * Binance Connect documented estimated quote:
 *
 * POST
 * /papi/v1/ramp/connect/buy/estimated-quote
 *
 * amountType = 1
 * significa que requestedAmount é fiat.
 *
 * Exemplo:
 *
 * MZN 640
 * ↓
 * Binance quote
 * ↓
 * USDT X
 * ======================================================= */

async function getEstimatedQuote(
  input
) {
  const amountMZN =
    safeNumber(
      input.amountMZN
    );

  if (
    !amountMZN ||
    amountMZN <= 0
  ) {
    throw new BinanceDefinitiveError(
      "amountMZN inválido."
    );
  }

  const paymentMethod =
    getConfiguredPaymentMethod();

  const body = {
    fiatCurrency:
      FIAT_CURRENCY,

    cryptoCurrency:
      CRYPTO_CURRENCY,

    requestedAmount:
      String(
        amountMZN
      ),

    /*
     * 1 = amount specified in fiat.
     */
    amountType: 1,

    network:
      NETWORK
  };

  /*
   * Não forçar método de pagamento se o administrador
   * não configurou um.
   *
   * Binance pode devolver o melhor método disponível.
   */
  if (paymentMethod) {
    body.payMethodCode =
      paymentMethod.payMethodCode;

    if (
      paymentMethod.payMethodSubCode
    ) {
      body.payMethodSubCode =
        paymentMethod.payMethodSubCode;
    }
  }

  const response =
    await request(
      "/papi/v1/ramp/connect/buy/estimated-quote",
      {
        method: "POST",

        body
      }
    );

  assertBinanceSuccess(
    response,
    "estimated-quote"
  );

  const data =
    extractData(response);

  if (!data) {
    throw new BinanceDefinitiveError(
      "Binance retornou quote vazia."
    );
  }

  const totalAmount =
    safeNumber(
      data.totalAmount
    );

  const quotePrice =
    safeNumber(
      data.quotePrice
    );

  if (
    !totalAmount ||
    totalAmount <= 0
  ) {
    throw new BinanceDefinitiveError(
      "Quantidade USDT retornada pela Binance é inválida.",
      {
        data
      }
    );
  }

  if (
    !quotePrice ||
    quotePrice <= 0
  ) {
    throw new BinanceDefinitiveError(
      "Preço retornado pela Binance é inválido.",
      {
        data
      }
    );
  }

  return {
    amountMZN,

    estimatedUSDT:
      round(
        totalAmount,
        8
      ),

    /*
     * Normalmente quotePrice representa
     * o preço na unidade fiat/crypto.
     */
    quotePrice:
      round(
        quotePrice,
        8
      ),

    effectiveRate:
      round(
        amountMZN /
          totalAmount,
        8
      ),

    feesMZN:
      String(
        data.feeCurrency ||
          ""
      ).toUpperCase() ===
      FIAT_CURRENCY
        ? safeNumber(
            data.feeAmount
          ) || 0
        : 0,

    feeAmount:
      safeNumber(
        data.feeAmount
      ) || 0,

    feeCurrency:
      data.feeCurrency ||
      null,

    networkFee:
      safeNumber(
        data.networkFee
      ) || 0,

    payMethodCode:
      data.payMethodCode ||
      null,

    payMethodSubCode:
      data.payMethodSubCode ||
      null,

    paymentAsset:
      FIAT_CURRENCY,

    settlementAsset:
      CRYPTO_CURRENCY,

    settlementAddress:
      TREASURY_ADDRESS,

    createdAt:
      new Date().toISOString(),

    /*
     * A documentação da quote não fornece necessariamente
     * um expiration timestamp no mesmo campo.
     *
     * O router deverá considerar a quote curta.
     */
    expiresAt:
      new Date(
        Date.now() + 10000
      ).toISOString(),

    raw:
      data
  };
}

/* =========================================================
 * PRE-VALIDATION
 * ======================================================= */

async function checkConfiguration() {
  if (
    !EXPLICITLY_ENABLED
  ) {
    return {
      configured: false,

      executionAvailable:
        false,

      reason:
        "Binance Connect está desativada por configuração."
    };
  }

  if (
    !API_KEY ||
    !API_SECRET
  ) {
    return {
      configured: false,

      executionAvailable:
        false,

      reason:
        "BINANCE_CONNECT_API_KEY/API_SECRET não configurados."
    };
  }

  if (
    !isValidTronAddress(
      TREASURY_ADDRESS
    )
  ) {
    return {
      configured: false,

      executionAvailable:
        false,

      reason:
        "USDTMZ_TRON_WALLET_ADDRESS inválido ou ausente."
    };
  }

  /*
   * Primeiro verificar se MZN existe realmente
   * na lista da Binance.
   */
  const fiat =
    await isMznSupported();

  if (!fiat.supported) {
    return {
      configured: true,

      executionAvailable:
        false,

      reason:
        "MZN não foi encontrado na lista de fiat suportado pela Binance Connect.",

      fiatSupported:
        false
    };
  }

  /*
   * Depois verificar USDT/TRON.
   */
  let network;

  try {
    network =
      await validateUSDTNetwork();
  } catch (error) {
    return {
      configured: true,

      executionAvailable:
        false,

      reason:
        error.message,

      fiatSupported:
        true
    };
  }

  /*
   * Depois verificar se existe método de pagamento.
   */
  let paymentMethods = [];

  try {
    paymentMethods =
      await getPaymentMethods();
  } catch (error) {
    return {
      configured: true,

      executionAvailable:
        false,

      reason:
        `Não foi possível obter métodos de pagamento: ${error.message}`,

      fiatSupported:
        true,

      network
    };
  }

  if (
    !paymentMethods.length
  ) {
    return {
      configured: true,

      executionAvailable:
        false,

      reason:
        "Binance não retornou método de pagamento disponível para MZN.",

      fiatSupported:
        true,

      network,

      paymentMethods
    };
  }

  return {
    configured: true,

    executionAvailable:
      true,

    fiatSupported:
      true,

    network,

    paymentMethods
  };
}

/* =========================================================
 * QUOTE ADAPTER
 * ======================================================= */

async function getQuote(
  input
) {
  /*
   * Não gerar quote se a rota não estiver
   * explicitamente habilitada.
   */
  if (
    !EXPLICITLY_ENABLED
  ) {
    throw new BinanceDefinitiveError(
      "Binance Connect está desativada."
    );
  }

  const config =
    await checkConfiguration();

  if (
    !config.executionAvailable
  ) {
    throw new BinanceDefinitiveError(
      config.reason ||
        "Binance Connect não está disponível.",
      config
    );
  }

  const quote =
    await getEstimatedQuote(
      input
    );

  /*
   * Segurança:
   * a cotação deve entregar para a carteira
   * controlada pela USDTMZ.
   */
  if (
    !isValidTronAddress(
      input.treasuryAddress
    )
  ) {
    throw new BinanceDefinitiveError(
      "Carteira de tesouraria TRON inválida."
    );
  }

  quote.settlementAddress =
    input.treasuryAddress;

  return quote;
}

/* =========================================================
 * LIQUIDITY CHECK
 * ======================================================= */

async function checkLiquidity(
  input,
  quote
) {
  /*
   * A própria existência de uma quote válida indica
   * que Binance encontrou uma rota/preço disponível
   * para a operação.
   *
   * Porém ainda NÃO significa execução.
   */
  if (
    !quote ||
    !quote.quotePrice ||
    !quote.estimatedUSDT
  ) {
    return {
      available: false,

      definitive: true,

      reason:
        "Quote Binance inválida."
    };
  }

  /*
   * Verificar novamente a validade da rede.
   */
  try {
    await validateUSDTNetwork();
  } catch (error) {
    return {
      available: false,

      definitive: true,

      reason:
        error.message
    };
  }

  return {
    available: true,

    definitive: false,

    availableUSDT:
      quote.estimatedUSDT,

    availablePaymentAsset:
      input.amountMZN,

    reason:
      "Binance retornou uma quote executável."
  };
}

/* =========================================================
 * EXECUTION
 *
 * ATENÇÃO:
 *
 * A Binance Connect possui APIs de quote/execução,
 * mas a execução final depende do produto/contrato
 * habilitado para a conta parceira.
 *
 * Não vamos inventar um endpoint de execução que
 * não esteja confirmado para a conta.
 *
 * Por isso, a variável:
 *
 * BINANCE_CONNECT_EXECUTE_ENDPOINT
 *
 * deve ser configurada somente com o endpoint
 * fornecido oficialmente à conta USDTMZ pela Binance.
 * ======================================================= */

function getExecuteEndpoint() {
  const endpoint =
    process.env.BINANCE_CONNECT_EXECUTE_ENDPOINT ||
    "";

  return endpoint;
}

async function execute(
  input,
  quote,
  idempotencyKey
) {
  if (
    !quote ||
    !quote.raw
  ) {
    throw new BinanceDefinitiveError(
      "Quote Binance ausente."
    );
  }

  /*
   * A execução precisa de uma autorização/contrato
   * real da Binance Connect.
   *
   * Não vamos usar um endpoint inventado.
   */
  const endpoint =
    getExecuteEndpoint();

  if (!endpoint) {
    throw new BinanceDefinitiveError(
      "BINANCE_CONNECT_EXECUTE_ENDPOINT não está configurado. A conta USDTMZ ainda precisa receber da Binance o endpoint/fluxo de execução habilitado.",
      {
        provider:
          "BINANCE_CONNECT",

        quoteId:
          quote.quoteId ||
          null,

        idempotencyKey
      }
    );
  }

  /*
   * Destination deve ser SEMPRE a tesouraria.
   */
  if (
    !isValidTronAddress(
      input.treasuryAddress
    )
  ) {
    throw new BinanceDefinitiveError(
      "Endereço da tesouraria TRON inválido."
    );
  }

  const body = {
    /*
     * O formato exato deve seguir o contrato
     * fornecido pela Binance para a conta.
     */
    quoteId:
      quote.quoteId ||
      quote.raw.quoteId ||
      null,

    fiatCurrency:
      FIAT_CURRENCY,

    cryptoCurrency:
      CRYPTO_CURRENCY,

    amount:
      String(
        input.amountMZN
      ),

    amountType: 1,

    network:
      NETWORK,

    address:
      input.treasuryAddress,

    clientOrderId:
      idempotencyKey
  };

  if (!body.quoteId) {
    throw new BinanceDefinitiveError(
      "Quote Binance não possui quoteId executável.",
      {
        quote:
          quote.raw
      }
    );
  }

  let response;

  try {
    response =
      await request(
        endpoint,
        {
          method: "POST",

          body
        }
      );
  } catch (error) {
    /*
     * Se Binance pode ter recebido a requisição,
     * não podemos simplesmente trocar de provider.
     */
    if (
      error instanceof
      BinanceDefinitiveError
    ) {
      throw error;
    }

    throw new BinanceUncertainError(
      "Não foi possível determinar se Binance recebeu a ordem.",
      {
        cause:
          error.message,

        quoteId:
          body.quoteId,

        idempotencyKey
      }
    );
  }

  /*
   * Se Binance explicitamente rejeitou antes de executar,
   * podemos considerar falha definitiva.
   */
  if (
    response?.success === false
  ) {
    throw new BinanceDefinitiveError(
      "Binance rejeitou a execução.",
      {
        response,

        quoteId:
          body.quoteId
      }
    );
  }

  const data =
    extractData(response);

  if (!data) {
    throw new BinanceUncertainError(
      "Binance não retornou dados de execução.",
      {
        response
      }
    );
  }

  const executionId =
    data.orderId ||
    data.transactionId ||
    data.id ||
    data.orderNo;

  if (!executionId) {
    throw new BinanceUncertainError(
      "Binance aceitou/repondeu sem identificador de execução.",
      {
        response
      }
    );
  }

  return {
    executionId:
      String(executionId),

    status:
      data.orderStatus ||
      data.status ||
      "PROCESSING",

    submitted: true,

    definitive:
      String(
        data.orderStatus ||
          data.status ||
          ""
      ).toUpperCase() ===
      "SUCCESS",

    raw:
      response
  };
}

/* =========================================================
 * EXECUTION STATUS
 * ======================================================= */

async function getExecutionStatus(
  input,
  execution
) {
  const executionId =
    execution.executionId;

  if (!executionId) {
    throw new BinanceUncertainError(
      "executionId ausente."
    );
  }

  /*
   * A conta Connect precisa fornecer o endpoint
   * de consulta de transação.
   *
   * A documentação oficial da Binance Connect
   * possui API de consulta de transações.
   */
  const endpoint =
    process.env.BINANCE_CONNECT_TRANSACTION_ENDPOINT ||
    "";

  if (!endpoint) {
    throw new BinanceUncertainError(
      "BINANCE_CONNECT_TRANSACTION_ENDPOINT não configurado.",
      {
        executionId
      }
    );
  }

  let response;

  try {
    response =
      await request(
        endpoint,
        {
          method: "POST",

          body: {
            transactionId:
              executionId,

            orderId:
              executionId
          }
        }
      );
  } catch (error) {
    throw new BinanceUncertainError(
      "Não foi possível consultar o estado da transação Binance.",
      {
        executionId,

        cause:
          error.message
      }
    );
  }

  const data =
    extractData(response);

  if (!data) {
    throw new BinanceUncertainError(
      "Binance não retornou estado da transação.",
      {
        executionId
      }
    );
  }

  const status =
    String(
      data.status ||
        data.orderStatus ||
        data.transactionStatus ||
        ""
    ).toUpperCase();

  /*
   * Não mapear estados desconhecidos para SUCCESS.
   */
  if (!status) {
    throw new BinanceUncertainError(
      "Estado da transação Binance desconhecido.",
      {
        executionId,

        response
      }
    );
  }

  return {
    status,

    executionId,

    raw:
      response
  };
}

/* =========================================================
 * ACQUIRED USDT
 * ======================================================= */

async function getAcquiredUSDT(
  input,
  execution
) {
  const status =
    await getExecutionStatus(
      input,
      execution
    );

  const data =
    extractData(
      status.raw
    );

  const statusName =
    String(
      status.status || ""
    ).toUpperCase();

  /*
   * Somente sucesso definitivo.
   */
  if (
    ![
      "SUCCESS",
      "COMPLETED",
      "COMPLETED_SUCCESS",
      "FINISHED"
    ].includes(statusName)
  ) {
    return {
      confirmed: false,

      amountUSDT: 0,

      status:
        statusName
    };
  }

  const amount =
    safeNumber(
      data?.cryptoAmount ||
        data?.receivedAmount ||
        data?.amount ||
        data?.totalAmount
    );

  if (
    !amount ||
    amount <= 0
  ) {
    throw new BinanceUncertainError(
      "Binance informou sucesso, mas não informou quantidade USDT válida.",
      {
        executionId:
          execution.executionId,

        response:
          status.raw
      }
    );
  }

  return {
    confirmed: true,

    amountUSDT:
      round(
        amount,
        8
      ),

    status:
      statusName,

    raw:
      status.raw
  };
}

/* =========================================================
 * SETTLEMENT
 * ======================================================= */

async function getSettlement(
  input,
  execution
) {
  const status =
    await getExecutionStatus(
      input,
      execution
    );

  const data =
    extractData(
      status.raw
    );

  const statusName =
    String(
      status.status || ""
    ).toUpperCase();

  if (
    ![
      "SUCCESS",
      "COMPLETED",
      "COMPLETED_SUCCESS",
      "FINISHED"
    ].includes(statusName)
  ) {
    return {
      settled: false,

      confirmed: false,

      status:
        statusName
    };
  }

  /*
   * A resposta precisa indicar que o USDT foi enviado
   * para o endereço da tesouraria.
   *
   * NÃO assumir settlement apenas porque a compra
   * foi bem-sucedida.
   */
  const destination =
    data?.address ||
    data?.destinationAddress ||
    data?.walletAddress ||
    data?.toAddress ||
    null;

  if (
    destination &&
    destination !==
      input.treasuryAddress
  ) {
    throw new BinanceDefinitiveError(
      "Binance informou settlement para endereço diferente da tesouraria.",
      {
        expected:
          input.treasuryAddress,

        received:
          destination,

        executionId:
          execution.executionId
      }
    );
  }

  /*
   * Se a API não informar destination, não podemos
   * afirmar que o USDT chegou à carteira.
   */
  if (
    !destination
  ) {
    return {
      settled: false,

      confirmed: false,

      status:
        statusName,

      reason:
        "Binance informou conclusão, mas não confirmou endereço de settlement."
    };
  }

  const txHash =
    data?.txHash ||
    data?.transactionHash ||
    data?.blockchainTxHash ||
    null;

  return {
    settled: true,

    confirmed: true,

    address:
      destination,

    txHash,

    status:
      statusName,

    raw:
      status.raw
  };
}

/* =========================================================
 * isConfigured
 * ======================================================= */

async function isConfigured() {
  const result =
    await checkConfiguration();

  return (
    result.configured === true
  );
}

/* =========================================================
 * ADAPTER
 * ======================================================= */

const adapter = {
  name:
    "BINANCE_CONNECT",

  /*
   * Só fica true se:
   *
   *   - explicitamente habilitado;
   *   - credenciais existem;
   *   - MZN existe na Binance;
   *   - USDT/TRON está disponível;
   *   - existe método de pagamento.
   *
   * A verificação completa acontece em
   * checkConfiguration().
   */
  executionAvailable:
    EXPLICITLY_ENABLED &&
    Boolean(
      API_KEY &&
        API_SECRET
    ),

  isConfigured,

  getQuote,

  checkLiquidity,

  execute,

  getExecutionStatus,

  getAcquiredUSDT,

  getSettlement,

  /*
   * Funções adicionais úteis para o painel/admin.
   */
  getFiatList,

  getPaymentMethods,

  getCryptoNetworks,

  validateUSDTNetwork,

  checkConfiguration
};

module.exports =
  adapter;

module.exports.BinanceLiquidityError =
  BinanceLiquidityError;

module.exports.BinanceDefinitiveError =
  BinanceDefinitiveError;

module.exports.BinanceUncertainError =
  BinanceUncertainError;
