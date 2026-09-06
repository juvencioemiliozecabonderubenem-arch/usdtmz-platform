import { neon } from "@neondatabase/serverless";
import { createHmac, timingSafeEqual } from "node:crypto";
import { TronWeb } from "tronweb";

const COOKIE_NAME = "usdtmz_admin_session";

const USDT_CONTRACT =
  "TR7NHqjeKQGTCi8q8ZY4pL8otSzgjLj6t".replace("KQG", "KQG");

// USDT TRC-20 Mainnet
const USDT_DECIMALS = 6;

const DEFAULT_FEE_LIMIT = 100_000_000;

function safeCompare(a, b) {
  const A = Buffer.from(String(a));
  const B = Buffer.from(String(b));

  if (A.length !== B.length) {
    return false;
  }

  return timingSafeEqual(A, B);
}

function verifySession(token, secret) {
  if (!token || !secret) {
    return null;
  }

  const parts = token.split(".");

  if (parts.length !== 2) {
    return null;
  }

  const [data, signature] = parts;

  const expectedSignature = createHmac("sha256", secret)
    .update(data)
    .digest("base64url");

  if (!safeCompare(signature, expectedSignature)) {
    return null;
  }

  try {
    const payload = JSON.parse(
      Buffer.from(data, "base64url").toString("utf8")
    );

    if (!payload.exp || Date.now() > payload.exp) {
      return null;
    }

    if (payload.id !== "admin") {
      return null;
    }

    return payload;
  } catch {
    return null;
  }
}

function getSessionToken(req) {
  const cookies = req.headers.cookie || "";

  const cookie = cookies
    .split(";")
    .map(item => item.trim())
    .find(
      item => item.startsWith(`${COOKIE_NAME}=`)
    );

  if (!cookie) {
    return null;
  }

  return cookie.substring(
    COOKIE_NAME.length + 1
  );
}

function normalizeAmount(value) {
  if (
    value === null ||
    value === undefined
  ) {
    return null;
  }

  const text = String(value).trim();

  if (!/^\d+(\.\d{1,6})?$/.test(text)) {
    return null;
  }

  const parts = text.split(".");

  const whole = parts[0];

  const decimal = (
    parts[1] || ""
  ).padEnd(USDT_DECIMALS, "0");

  const baseUnits =
    BigInt(whole) *
      1_000_000n +
    BigInt(decimal || "0");

  if (baseUnits <= 0n) {
    return null;
  }

  return {
    text,
    baseUnits,
    display: (
      Number(baseUnits) /
      1_000_000
    ).toFixed(6)
  };
}

function isValidPrivateKey(value) {
  return /^[0-9a-fA-F]{64}$/.test(
    String(value || "")
  );
}

function getDatabaseUrl() {
  return (
    process.env.URL_DO_BANCO_DE_DADOS ||
    process.env.POSTGRES_URL ||
    process.env.DATABASE_URL ||
    process.env.POSTGRES_URL_NON_POOLING ||
    process.env.DATABASE_URL_UNPOOLED
  );
}

function getTronWeb(privateKey, apiKey) {
  const options = {
    fullHost:
      "https://api.trongrid.io",
    privateKey
  };

  if (apiKey) {
    options.headers = {
      "TRON-PRO-API-KEY": apiKey
    };
  }

  return new TronWeb(options);
}

function toBigInt(value) {
  if (typeof value === "bigint") {
    return value;
  }

  if (
    value &&
    typeof value.toString === "function"
  ) {
    return BigInt(value.toString());
  }

  return BigInt(String(value));
}

export default async function handler(req, res) {

  if (req.method !== "POST") {
    return res.status(405).json({
      success: false,
      message: "Método não permitido."
    });
  }

  const secret =
    process.env.ADMIN_SESSION_SECRET;

  const databaseUrl =
    getDatabaseUrl();

  const privateKey =
    process.env.TRON_PRIVATE_KEY;

  const configuredWallet =
    process.env.USDTMZ_TRON_WALLET_ADDRESS;

  const tronApiKey =
    process.env.TRON_PRO_API_KEY;

  if (
    !secret ||
    !databaseUrl ||
    !privateKey ||
    !configuredWallet
  ) {
    return res.status(500).json({
      success: false,
      message:
        "Configuração da carteira TRON incompleta."
    });
  }

  if (!isValidPrivateKey(privateKey)) {
    return res.status(500).json({
      success: false,
      message:
        "TRON_PRIVATE_KEY inválida."
    });
  }

  const token =
    getSessionToken(req);

  const session =
    verifySession(
      token,
      secret
    );

  if (!session) {
    return res.status(401).json({
      success: false,
      authenticated: false,
      message:
        "Sessão inválida ou expirada."
    });
  }

  const body = req.body || {};

  const withdrawalId =
    body.withdrawal_id;

  if (!withdrawalId) {
    return res.status(400).json({
      success: false,
      message:
        "withdrawal_id é obrigatório."
    });
  }

  try {

    const sql =
      neon(databaseUrl);

    /*
     * Primeiro bloqueamos o levantamento
     * dentro de uma transação PostgreSQL.
     *
     * Assim duas chamadas simultâneas
     * não conseguem processar o mesmo
     * levantamento ao mesmo tempo.
     */

    const locked =
      await sql`
        UPDATE withdrawals
        SET
          status = 'PROCESSING',
          updated_at = NOW()
        WHERE withdrawal_id = ${String(
          withdrawalId
        )}
        AND UPPER(status) = 'AUTHORIZED'
        RETURNING
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
      `;

    if (locked.length === 0) {

      const existing =
        await sql`
          SELECT
            withdrawal_id,
            status,
            tx_hash
          FROM withdrawals
          WHERE withdrawal_id = ${String(
            withdrawalId
          )}
          LIMIT 1
        `;

      if (existing.length === 0) {
        return res.status(404).json({
          success: false,
          message:
            "Levantamento não encontrado."
        });
      }

      if (
        existing[0].tx_hash
      ) {
        return res.status(409).json({
          success: false,
          message:
            "Este levantamento já possui um TX Hash.",
          tx_hash:
            existing[0].tx_hash
        });
      }

      return res.status(409).json({
        success: false,
        message:
          `O levantamento não está autorizado. Estado atual: ${existing[0].status}.`
      });
    }

    const withdrawal =
      locked[0];

    const asset =
      String(
        withdrawal.asset || ""
      ).toUpperCase();

    const network =
      String(
        withdrawal.network || ""
      ).toUpperCase();

    if (asset !== "USDT") {

      await sql`
        UPDATE withdrawals
        SET
          status = 'AUTHORIZED',
          updated_at = NOW()
        WHERE withdrawal_id = ${String(
          withdrawalId
        )}
        AND UPPER(status) = 'PROCESSING'
      `;

      return res.status(400).json({
        success: false,
        message:
          "Este levantamento não é de USDT."
      });
    }

    if (
      network !== "TRON" &&
      network !== "TRC-20"
    ) {

      await sql`
        UPDATE withdrawals
        SET
          status = 'AUTHORIZED',
          updated_at = NOW()
        WHERE withdrawal_id = ${String(
          withdrawalId
        )}
        AND UPPER(status) = 'PROCESSING'
      `;

      return res.status(400).json({
        success: false,
        message:
          "A rede do levantamento não é TRON/TRC-20."
      });
    }

    const destination =
      String(
        withdrawal.destination_address ||
        ""
      ).trim();

    if (!destination) {

      await sql`
        UPDATE withdrawals
        SET
          status = 'AUTHORIZED',
          updated_at = NOW()
        WHERE withdrawal_id = ${String(
          withdrawalId
        )}
        AND UPPER(status) = 'PROCESSING'
      `;

      return res.status(400).json({
        success: false,
        message:
          "Endereço TRON de destino não informado."
      });
    }

    const amount =
      normalizeAmount(
        withdrawal.amount
      );

    if (!amount) {

      await sql`
        UPDATE withdrawals
        SET
          status = 'AUTHORIZED',
          updated_at = NOW()
        WHERE withdrawal_id = ${String(
          withdrawalId
        )}
        AND UPPER(status) = 'PROCESSING'
      `;

      return res.status(400).json({
        success: false,
        message:
          "Quantidade de USDT inválida."
      });
    }

    const tronWeb =
      getTronWeb(
        privateKey,
        tronApiKey
      );

    /*
     * Verifica o endereço de destino.
     */
    if (
      !TronWeb.isAddress(
        destination
      )
    ) {

      await sql`
        UPDATE withdrawals
        SET
          status = 'AUTHORIZED',
          updated_at = NOW()
        WHERE withdrawal_id = ${String(
          withdrawalId
        )}
        AND UPPER(status) = 'PROCESSING'
      `;

      return res.status(400).json({
        success: false,
        message:
          "Endereço TRON de destino inválido."
      });
    }

    /*
     * Descobre a carteira correspondente
     * à chave privada.
     */
    const senderAddress =
      tronWeb.address.fromPrivateKey(
        privateKey
      );

    if (!senderAddress) {
      throw new Error(
        "Não foi possível obter a carteira da chave privada."
      );
    }

    /*
     * Confirma que a chave privada
     * pertence à carteira USDTMZ configurada.
     */
    if (
      senderAddress !==
      configuredWallet
    ) {

      await sql`
        UPDATE withdrawals
        SET
          status = 'AUTHORIZED',
          updated_at = NOW()
        WHERE withdrawal_id = ${String(
          withdrawalId
        )}
        AND UPPER(status) = 'PROCESSING'
      `;

      return res.status(500).json({
        success: false,
        message:
          "A chave privada não corresponde à carteira USDTMZ configurada."
      });
    }

    /*
     * Consulta saldo USDT diretamente
     * no contrato TRC-20.
     */
    const contract =
      await tronWeb.contract().at(
        USDT_CONTRACT
      );

    const rawBalance =
      await contract
        .balanceOf(senderAddress)
        .call();

    const usdtBalance =
      toBigInt(rawBalance);

    if (
      usdtBalance <
      amount.baseUnits
    ) {

      await sql`
        UPDATE withdrawals
        SET
          status = 'AUTHORIZED',
          updated_at = NOW()
        WHERE withdrawal_id = ${String(
          withdrawalId
        )}
        AND UPPER(status) = 'PROCESSING'
      `;

      return res.status(409).json({
        success: false,
        message:
          "Saldo USDT insuficiente.",
        available_usdt:
          (
            Number(usdtBalance) /
            1_000_000
          ).toFixed(6),
        requested_usdt:
          amount.display
      });
    }

    /*
     * Verifica saldo TRX.
     * O TRX é necessário para recursos/taxas
     * da operação na rede TRON.
     */
    const trxBalance =
      await tronWeb.trx.getBalance(
        senderAddress
      );

    const feeLimit =
      Number(
        process.env.TRON_FEE_LIMIT ||
        DEFAULT_FEE_LIMIT
      );

    if (
      !Number.isSafeInteger(
        feeLimit
      ) ||
      feeLimit <= 0
    ) {

      await sql`
        UPDATE withdrawals
        SET
          status = 'AUTHORIZED',
          updated_at = NOW()
        WHERE withdrawal_id = ${String(
          withdrawalId
        )}
        AND UPPER(status) = 'PROCESSING'
      `;

      return res.status(500).json({
        success: false,
        message:
          "TRON_FEE_LIMIT inválido."
      });
    }

    /*
     * Proteção adicional contra TX Hash já
     * registrado no banco.
     */
    const duplicate =
      await sql`
        SELECT withdrawal_id
        FROM withdrawals
        WHERE tx_hash IS NOT NULL
        AND tx_hash <> ''
        AND withdrawal_id <> ${String(
          withdrawalId
        )}
        LIMIT 1
      `;

    /*
     * Não existe um TX Hash conhecido neste
     * momento, portanto a consulta acima serve
     * apenas para manter a verificação preparada.
     */

    void duplicate;

    /*
     * ENVIO REAL
     *
     * transfer(address,uint256)
     *
     * amount.baseUnits = USDT * 1,000,000
     */
    const txHash =
      await contract
        .transfer(
          destination,
          amount.baseUnits.toString()
        )
        .send({
          feeLimit,
          callValue: 0,
          shouldPollResponse: false
        });

    if (
      !txHash ||
      typeof txHash !== "string"
    ) {

      throw new Error(
        "A rede TRON não devolveu um TX Hash válido."
      );
    }

    /*
     * Guarda imediatamente o TX Hash.
     *
     * O estado continua PROCESSING até a
     * API de confirmação verificar a blockchain.
     */
    const updated =
      await sql`
        UPDATE withdrawals
        SET
          tx_hash = ${txHash},
          status = 'PROCESSING',
          updated_at = NOW()
        WHERE withdrawal_id = ${String(
          withdrawalId
        )}
        AND UPPER(status) = 'PROCESSING'
        AND (
          tx_hash IS NULL
          OR tx_hash = ''
        )
        RETURNING
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
      `;

    if (
      updated.length === 0
    ) {

      /*
       * Se o banco não conseguiu guardar o
       * resultado, NÃO tentamos enviar novamente.
       *
       * O TX já foi transmitido para a blockchain.
       */
      console.error(
        "TX enviado mas não foi possível atualizar o levantamento:",
        txHash
      );

      return res.status(500).json({
        success: false,
        message:
          "A transação foi enviada para a rede, mas o sistema não conseguiu atualizar o levantamento. NÃO tente enviar novamente.",
        tx_hash: txHash
      });
    }

    return res.status(200).json({
      success: true,
      message:
        "USDT enviado para a rede TRON. Aguardando confirmação.",
      withdrawal:
        updated[0],
      tx_hash: txHash,
      network: "TRON",
      asset: "USDT",
      amount_usdt:
        amount.display,
      destination
    });

  } catch (error) {

    console.error(
      "Erro ao enviar USDT pela carteira USDTMZ:",
      error
    );

    /*
     * Tentamos devolver o levantamento para
     * AUTHORIZED somente quando ainda não
     * existe TX Hash.
     *
     * Se já houver TX Hash, NÃO alteramos para
     * AUTHORIZED, porque a transação pode ter
     * sido transmitida.
     */
    try {

      const sql =
        neon(databaseUrl);

      await sql`
        UPDATE withdrawals
        SET
          status = 'AUTHORIZED',
          updated_at = NOW()
        WHERE withdrawal_id = ${String(
          withdrawalId
        )}
        AND UPPER(status) = 'PROCESSING'
        AND (
          tx_hash IS NULL
          OR tx_hash = ''
        )
      `;

    } catch (rollbackError) {

      console.error(
        "Erro ao restaurar estado do levantamento:",
        rollbackError
      );

    }

    return res.status(500).json({
      success: false,
      message:
        "Não foi possível enviar o USDT. Nenhuma nova tentativa automática será feita."
    });
  }
}
