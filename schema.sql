-- ============================================================
-- USDTMZ — BASE DE DADOS FINANCEIRA
-- ADMIN / TESOURARIA / EXCHANGE RATE / USDT TRC20
-- ============================================================
-- IMPORTANTE:
-- 1. PostgreSQL / Vercel
-- 2. Não contém chaves privadas nem API secrets
-- 3. Não cria API13
-- 4. Valores financeiros usam NUMERIC
-- 5. A blockchain continua sendo a fonte da verdade para USDT/TRX
-- ============================================================


-- ============================================================
-- 1. UTILIZADORES
-- ============================================================

CREATE TABLE IF NOT EXISTS users (
    id BIGSERIAL PRIMARY KEY,

    name VARCHAR(120) NOT NULL,

    email VARCHAR(180) UNIQUE NOT NULL,

    phone VARCHAR(30) UNIQUE,

    password_hash TEXT NOT NULL,

    status VARCHAR(20) NOT NULL DEFAULT 'ACTIVE'
        CHECK (status IN ('ACTIVE', 'BLOCKED', 'SUSPENDED')),

    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);


-- ============================================================
-- 2. CARTEIRAS DOS UTILIZADORES
-- ============================================================

CREATE TABLE IF NOT EXISTS wallets (
    id BIGSERIAL PRIMARY KEY,

    user_id BIGINT NOT NULL UNIQUE
        REFERENCES users(id)
        ON DELETE CASCADE,

    usdt_balance NUMERIC(30, 8) NOT NULL DEFAULT 0
        CHECK (usdt_balance >= 0),

    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);


-- ============================================================
-- 3. COMPRAS DE USDT DOS UTILIZADORES
-- ============================================================

CREATE TABLE IF NOT EXISTS purchases (
    id BIGSERIAL PRIMARY KEY,

    user_id BIGINT NOT NULL
        REFERENCES users(id)
        ON DELETE RESTRICT,

    amount_mzn NUMERIC(20, 2) NOT NULL
        CHECK (amount_mzn > 0),

    amount_usdt NUMERIC(30, 8) NOT NULL
        CHECK (amount_usdt > 0),

    payment_method VARCHAR(30) NOT NULL
        CHECK (
            payment_method IN (
                'MPESA',
                'EMOLA',
                'PAGAR'
            )
        ),

    status VARCHAR(30) NOT NULL DEFAULT 'PENDING'
        CHECK (
            status IN (
                'PENDING',
                'PAID',
                'CREDITED',
                'FAILED',
                'CANCELLED'
            )
        ),

    payment_reference VARCHAR(150),

    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);


-- ============================================================
-- 4. LEVANTAMENTOS
-- ============================================================

CREATE TABLE IF NOT EXISTS withdrawals (
    id BIGSERIAL PRIMARY KEY,

    user_id BIGINT NOT NULL
        REFERENCES users(id)
        ON DELETE RESTRICT,

    amount_usdt NUMERIC(30, 8) NOT NULL
        CHECK (amount_usdt > 0),

    wallet_address VARCHAR(100) NOT NULL,

    network VARCHAR(20) NOT NULL DEFAULT 'TRC20'
        CHECK (network = 'TRC20'),

    status VARCHAR(30) NOT NULL DEFAULT 'PENDING'
        CHECK (
            status IN (
                'PENDING',
                'AUTHORIZED',
                'REJECTED',
                'PROCESSING',
                'COMPLETED',
                'FAILED'
            )
        ),

    transaction_hash VARCHAR(100),

    rejection_reason TEXT,

    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    authorized_at TIMESTAMPTZ,

    processed_at TIMESTAMPTZ,

    completed_at TIMESTAMPTZ,

    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);


-- ============================================================
-- 5. HISTÓRICO EXISTENTE DE MOVIMENTAÇÕES
-- ============================================================

CREATE TABLE IF NOT EXISTS transactions (
    id BIGSERIAL PRIMARY KEY,

    user_id BIGINT NOT NULL
        REFERENCES users(id)
        ON DELETE RESTRICT,

    type VARCHAR(30) NOT NULL
        CHECK (
            type IN (
                'DEPOSIT',
                'PURCHASE',
                'WITHDRAWAL',
                'REFUND',
                'ADJUSTMENT'
            )
        ),

    amount_usdt NUMERIC(30, 8) NOT NULL
        CHECK (amount_usdt <> 0),

    reference_id BIGINT,

    description TEXT,

    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);


-- ============================================================
-- 6. LOG DE AÇÕES ADMINISTRATIVAS
-- ============================================================

CREATE TABLE IF NOT EXISTS admin_audit_logs (
    id BIGSERIAL PRIMARY KEY,

    admin_id VARCHAR(100) NOT NULL,

    action VARCHAR(100) NOT NULL,

    entity_type VARCHAR(50),

    entity_id BIGINT,

    details JSONB,

    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);


-- ============================================================
-- 7. ORDENS FINANCEIRAS ADMIN
-- ============================================================
-- Usada para:
-- MZN -> USDT
-- pagamento -> confirmação -> reserva -> TRON -> Binance
--
-- A ordem guarda a cotação congelada.
-- O valor aprovado não deve ser recalculado durante o processamento.
-- ============================================================

CREATE TABLE IF NOT EXISTS orders (
    id BIGSERIAL PRIMARY KEY,

    order_id VARCHAR(120) UNIQUE NOT NULL,

    operation VARCHAR(50) NOT NULL
        CHECK (
            operation IN (
                'BUY_USDT_ADMIN'
            )
        ),

    status VARCHAR(40) NOT NULL DEFAULT 'PENDING'
        CHECK (
            status IN (
                'PENDING',
                'PAYMENT_PENDING',
                'PAYMENT_CONFIRMED',
                'RESERVED',
                'PROCESSING',
                'USDT_SENT',
                'COMPLETED',
                'FAILED',
                'CANCELLED'
            )
        ),

    payment_method VARCHAR(30)
        CHECK (
            payment_method IS NULL
            OR payment_method IN (
                'MPESA',
                'EMOLA',
                'MKESH',
                'CARD',
                'BANK',
                'PAGAR'
            )
        ),

    amount_mzn NUMERIC(20, 2) NOT NULL
        CHECK (amount_mzn > 0),

    usdt_amount NUMERIC(30, 8) NOT NULL
        CHECK (usdt_amount > 0),

    rate_mzn_usdt NUMERIC(30, 12) NOT NULL
        CHECK (rate_mzn_usdt > 0),

    market_rate_mzn_usdt NUMERIC(30, 12),

    spread_percent NUMERIC(12, 6),

    quote_source VARCHAR(100),

    quote_created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    quote_expires_at TIMESTAMPTZ,

    payer_name VARCHAR(150),

    payer_phone VARCHAR(50),

    pagar_payment_id VARCHAR(150),

    pagar_event_id VARCHAR(200),

    payment_reference VARCHAR(200),

    payment_currency VARCHAR(10) DEFAULT 'MZN',

    payment_amount NUMERIC(20, 2),

    payment_confirmed_at TIMESTAMPTZ,

    reserved_usdt NUMERIC(30, 8) NOT NULL DEFAULT 0
        CHECK (reserved_usdt >= 0),

    destination_address VARCHAR(100),

    destination_network VARCHAR(20) DEFAULT 'TRC20'
        CHECK (
            destination_network IS NULL
            OR destination_network = 'TRC20'
        ),

    transaction_hash VARCHAR(100),

    transaction_confirmed_at TIMESTAMPTZ,

    failure_reason TEXT,

    metadata JSONB NOT NULL DEFAULT '{}'::jsonb,

    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);


-- ============================================================
-- 8. TESOURARIA CENTRAL
-- ============================================================
-- Uma única linha representa a posição interna da tesouraria.
--
-- ATENÇÃO:
-- usdt_onchain_balance = último saldo real conhecido da TRON
-- usdt_reserved       = USDT comprometido por operações
-- usdt_available      = calculado pelo sistema
-- ============================================================

CREATE TABLE IF NOT EXISTS treasury_wallet (
    id SMALLINT PRIMARY KEY DEFAULT 1,

    currency VARCHAR(10) NOT NULL DEFAULT 'MIXED',

    mzn_balance NUMERIC(30, 2) NOT NULL DEFAULT 0
        CHECK (mzn_balance >= 0),

    usdt_onchain_balance NUMERIC(30, 8) NOT NULL DEFAULT 0
        CHECK (usdt_onchain_balance >= 0),

    trx_onchain_balance NUMERIC(30, 6) NOT NULL DEFAULT 0
        CHECK (trx_onchain_balance >= 0),

    usdt_reserved NUMERIC(30, 8) NOT NULL DEFAULT 0
        CHECK (usdt_reserved >= 0),

    mzn_reserved NUMERIC(30, 2) NOT NULL DEFAULT 0
        CHECK (mzn_reserved >= 0),

    last_blockchain_sync_at TIMESTAMPTZ,

    last_financial_sync_at TIMESTAMPTZ,

    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);


-- Garante a existência da tesouraria principal.
INSERT INTO treasury_wallet (
    id,
    currency
)
VALUES (
    1,
    'MIXED'
)
ON CONFLICT (id) DO NOTHING;


-- ============================================================
-- 9. DEPÓSITOS DA TESOURARIA
-- ============================================================

CREATE TABLE IF NOT EXISTS treasury_deposits (
    id BIGSERIAL PRIMARY KEY,

    source VARCHAR(50) NOT NULL
        CHECK (
            source IN (
                'MPESA',
                'EMOLA',
                'MKESH',
                'BANK',
                'USDT_TRON',
                'EXTERNAL_WALLET',
                'USDT_PURCHASE',
                'LIQUIDITY_PARTNER',
                'BINANCE',
                'KOTANI',
                'REDPAY',
                'MANUAL_APPROVED'
            )
        ),

    currency VARCHAR(10) NOT NULL
        CHECK (
            currency IN (
                'MZN',
                'USDT',
                'TRX'
            )
        ),

    amount NUMERIC(30, 8) NOT NULL
        CHECK (amount > 0),

    external_reference VARCHAR(200),

    blockchain_tx_hash VARCHAR(100),

    status VARCHAR(30) NOT NULL DEFAULT 'PENDING'
        CHECK (
            status IN (
                'PENDING',
                'CONFIRMED',
                'REJECTED',
                'CANCELLED'
            )
        ),

    description TEXT,

    metadata JSONB NOT NULL DEFAULT '{}'::jsonb,

    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    confirmed_at TIMESTAMPTZ
);


-- ============================================================
-- 10. RESERVAS DE USDT
-- ============================================================
-- Esta tabela é fundamental para impedir que duas operações
-- gastem o mesmo USDT simultaneamente.
-- ============================================================

CREATE TABLE IF NOT EXISTS treasury_reservations (
    id BIGSERIAL PRIMARY KEY,

    order_id BIGINT REFERENCES orders(id)
        ON DELETE RESTRICT,

    external_order_id VARCHAR(120),

    amount_usdt NUMERIC(30, 8) NOT NULL
        CHECK (amount_usdt > 0),

    status VARCHAR(30) NOT NULL DEFAULT 'RESERVED'
        CHECK (
            status IN (
                'RESERVED',
                'RELEASED',
                'CONSUMED',
                'CANCELLED'
            )
        ),

    reason VARCHAR(100),

    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    released_at TIMESTAMPTZ,

    consumed_at TIMESTAMPTZ,

    metadata JSONB NOT NULL DEFAULT '{}'::jsonb
);


-- Uma ordem não pode possuir duas reservas ativas.
CREATE UNIQUE INDEX IF NOT EXISTS ux_treasury_reservation_active_order
    ON treasury_reservations(order_id)
    WHERE status = 'RESERVED';


-- ============================================================
-- 11. CONVERSÕES MZN -> USDT
-- ============================================================

CREATE TABLE IF NOT EXISTS treasury_conversions (
    id BIGSERIAL PRIMARY KEY,

    order_id BIGINT REFERENCES orders(id)
        ON DELETE RESTRICT,

    amount_mzn NUMERIC(30, 2) NOT NULL
        CHECK (amount_mzn > 0),

    market_rate NUMERIC(30, 12) NOT NULL
        CHECK (market_rate > 0),

    execution_rate NUMERIC(30, 12) NOT NULL
        CHECK (execution_rate > 0),

    spread_percent NUMERIC(12, 6),

    amount_usdt NUMERIC(30, 8) NOT NULL
        CHECK (amount_usdt > 0),

    status VARCHAR(30) NOT NULL DEFAULT 'PENDING'
        CHECK (
            status IN (
                'PENDING',
                'RESERVED',
                'COMPLETED',
                'CANCELLED',
                'FAILED'
            )
        ),

    source VARCHAR(100),

    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    completed_at TIMESTAMPTZ
);


-- ============================================================
-- 12. EXCHANGE RATE
-- ============================================================
-- Guarda as cotações utilizadas pelo Admin.
--
-- market_rate:
-- referência externa.
--
-- execution_rate:
-- taxa efetivamente oferecida pela USDTMZ.
--
-- A ordem guarda sua própria cópia da taxa para ficar congelada.
-- ============================================================

CREATE TABLE IF NOT EXISTS exchange_rates (
    id BIGSERIAL PRIMARY KEY,

    base_currency VARCHAR(10) NOT NULL DEFAULT 'USDT',

    quote_currency VARCHAR(10) NOT NULL DEFAULT 'MZN',

    market_rate NUMERIC(30, 12) NOT NULL
        CHECK (market_rate > 0),

    execution_rate NUMERIC(30, 12) NOT NULL
        CHECK (execution_rate > 0),

    spread_percent NUMERIC(12, 6) NOT NULL DEFAULT 0,

    source VARCHAR(100) NOT NULL,

    fetched_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    expires_at TIMESTAMPTZ,

    is_active BOOLEAN NOT NULL DEFAULT TRUE,

    metadata JSONB NOT NULL DEFAULT '{}'::jsonb
);


-- ============================================================
-- 13. LEDGER FINANCEIRO CENTRAL
-- ============================================================
-- Este é o histórico contábil da tesouraria.
--
-- Não usamos FLOAT/DOUBLE.
-- Valores financeiros ficam em NUMERIC.
--
-- amount pode representar MZN, USDT ou TRX.
-- ============================================================

CREATE TABLE IF NOT EXISTS treasury_ledger (
    id BIGSERIAL PRIMARY KEY,

    currency VARCHAR(10) NOT NULL
        CHECK (
            currency IN (
                'MZN',
                'USDT',
                'TRX'
            )
        ),

    entry_type VARCHAR(50) NOT NULL
        CHECK (
            entry_type IN (
                'DEPOSIT',
                'PAYMENT_RECEIVED',
                'PURCHASE',
                'RESERVATION',
                'RESERVATION_RELEASE',
                'WITHDRAWAL',
                'TRANSFER',
                'REFUND',
                'FEE',
                'ADJUSTMENT',
                'CONVERSION',
                'REVERSAL'
            )
        ),

    direction VARCHAR(10) NOT NULL
        CHECK (
            direction IN (
                'CREDIT',
                'DEBIT'
            )
        ),

    amount NUMERIC(30, 8) NOT NULL
        CHECK (amount > 0),

    balance_after NUMERIC(30, 8),

    reference_type VARCHAR(50),

    reference_id VARCHAR(200),

    order_id BIGINT REFERENCES orders(id)
        ON DELETE RESTRICT,

    external_reference VARCHAR(200),

    transaction_hash VARCHAR(100),

    description TEXT,

    metadata JSONB NOT NULL DEFAULT '{}'::jsonb,

    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);


-- ============================================================
-- 14. TRANSAÇÕES BLOCKCHAIN
-- ============================================================

CREATE TABLE IF NOT EXISTS blockchain_transactions (
    id BIGSERIAL PRIMARY KEY,

    network VARCHAR(20) NOT NULL DEFAULT 'TRON'
        CHECK (network = 'TRON'),

    token VARCHAR(20) NOT NULL DEFAULT 'USDT',

    contract_address VARCHAR(100),

    transaction_hash VARCHAR(100) UNIQUE NOT NULL,

    from_address VARCHAR(100),

    to_address VARCHAR(100),

    amount NUMERIC(30, 8),

    status VARCHAR(30) NOT NULL DEFAULT 'PENDING'
        CHECK (
            status IN (
                'PENDING',
                'BROADCAST',
                'CONFIRMED',
                'FAILED',
                'UNKNOWN'
            )
        ),

    confirmations INTEGER NOT NULL DEFAULT 0
        CHECK (confirmations >= 0),

    block_number BIGINT,

    fee_trx NUMERIC(30, 6),

    order_id BIGINT REFERENCES orders(id)
        ON DELETE RESTRICT,

    withdrawal_id BIGINT,

    raw_data JSONB,

    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    confirmed_at TIMESTAMPTZ
);


-- ============================================================
-- 15. SAÍDAS DA TESOURARIA
-- ============================================================

CREATE TABLE IF NOT EXISTS treasury_withdrawals (
    id BIGSERIAL PRIMARY KEY,

    order_id BIGINT REFERENCES orders(id)
        ON DELETE RESTRICT,

    withdrawal_id BIGINT,

    destination_address VARCHAR(100) NOT NULL,

    network VARCHAR(20) NOT NULL DEFAULT 'TRC20'
        CHECK (network = 'TRC20'),

    currency VARCHAR(10) NOT NULL DEFAULT 'USDT'
        CHECK (currency = 'USDT'),

    amount NUMERIC(30, 8) NOT NULL
        CHECK (amount > 0),

    status VARCHAR(30) NOT NULL DEFAULT 'PENDING'
        CHECK (
            status IN (
                'PENDING',
                'AUTHORIZED',
                'PROCESSING',
                'BROADCAST',
                'CONFIRMED',
                'COMPLETED',
                'FAILED',
                'UNKNOWN',
                'CANCELLED'
            )
        ),

    transaction_hash VARCHAR(100),

    failure_reason TEXT,

    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    authorized_at TIMESTAMPTZ,

    processing_at TIMESTAMPTZ,

    completed_at TIMESTAMPTZ,

    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);


-- ============================================================
-- 16. EVENTOS WEBHOOK PAGAR
-- ============================================================
-- Idempotência:
-- o mesmo evento externo não deve produzir dois créditos.
-- ============================================================

CREATE TABLE IF NOT EXISTS pagar_webhook_events (
    id BIGSERIAL PRIMARY KEY,

    event_id VARCHAR(200) UNIQUE NOT NULL,

    event_type VARCHAR(100),

    payment_id VARCHAR(200),

    reference VARCHAR(200),

    status VARCHAR(50),

    payload JSONB NOT NULL,

    signature_valid BOOLEAN NOT NULL DEFAULT FALSE,

    processed_at TIMESTAMPTZ,

    processing_error TEXT,

    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);


-- ============================================================
-- 17. LOCK / OPERAÇÕES FINANCEIRAS
-- ============================================================
-- Ajuda a controlar processamento único de uma operação.
-- ============================================================

CREATE TABLE IF NOT EXISTS financial_operations (
    id BIGSERIAL PRIMARY KEY,

    operation_key VARCHAR(200) UNIQUE NOT NULL,

    operation_type VARCHAR(80) NOT NULL,

    status VARCHAR(40) NOT NULL DEFAULT 'PROCESSING'
        CHECK (
            status IN (
                'PROCESSING',
                'COMPLETED',
                'FAILED',
                'UNKNOWN'
            )
        ),

    reference_id VARCHAR(200),

    result JSONB,

    error_message TEXT,

    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    completed_at TIMESTAMPTZ,

    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);


-- ============================================================
-- 18. ÍNDICES
-- ============================================================

CREATE INDEX IF NOT EXISTS idx_users_email
    ON users(email);

CREATE INDEX IF NOT EXISTS idx_wallets_user_id
    ON wallets(user_id);

CREATE INDEX IF NOT EXISTS idx_purchases_user_id
    ON purchases(user_id);

CREATE INDEX IF NOT EXISTS idx_purchases_status
    ON purchases(status);

CREATE INDEX IF NOT EXISTS idx_withdrawals_user_id
    ON withdrawals(user_id);

CREATE INDEX IF NOT EXISTS idx_withdrawals_status
    ON withdrawals(status);

CREATE INDEX IF NOT EXISTS idx_withdrawals_transaction_hash
    ON withdrawals(transaction_hash);

CREATE INDEX IF NOT EXISTS idx_transactions_user_id
    ON transactions(user_id);

CREATE INDEX IF NOT EXISTS idx_admin_audit_logs_created_at
    ON admin_audit_logs(created_at);

CREATE INDEX IF NOT EXISTS idx_orders_status
    ON orders(status);

CREATE INDEX IF NOT EXISTS idx_orders_operation
    ON orders(operation);

CREATE INDEX IF NOT EXISTS idx_orders_pagar_payment_id
    ON orders(pagar_payment_id);

CREATE INDEX IF NOT EXISTS idx_orders_payment_reference
    ON orders(payment_reference);

CREATE INDEX IF NOT EXISTS idx_orders_transaction_hash
    ON orders(transaction_hash);

CREATE INDEX IF NOT EXISTS idx_treasury_deposits_status
    ON treasury_deposits(status);

CREATE INDEX IF NOT EXISTS idx_treasury_deposits_reference
    ON treasury_deposits(external_reference);

CREATE INDEX IF NOT EXISTS idx_treasury_reservations_status
    ON treasury_reservations(status);

CREATE INDEX IF NOT EXISTS idx_treasury_reservations_order
    ON treasury_reservations(order_id);

CREATE INDEX IF NOT EXISTS idx_treasury_conversions_order
    ON treasury_conversions(order_id);

CREATE INDEX IF NOT EXISTS idx_exchange_rates_active
    ON exchange_rates(is_active);

CREATE INDEX IF NOT EXISTS idx_exchange_rates_fetched
    ON exchange_rates(fetched_at DESC);

CREATE INDEX IF NOT EXISTS idx_treasury_ledger_currency
    ON treasury_ledger(currency);

CREATE INDEX IF NOT EXISTS idx_treasury_ledger_order
    ON treasury_ledger(order_id);

CREATE INDEX IF NOT EXISTS idx_treasury_ledger_reference
    ON treasury_ledger(reference_id);

CREATE INDEX IF NOT EXISTS idx_treasury_ledger_created
    ON treasury_ledger(created_at DESC);

CREATE INDEX IF NOT EXISTS idx_blockchain_transactions_order
    ON blockchain_transactions(order_id);

CREATE INDEX IF NOT EXISTS idx_blockchain_transactions_status
    ON blockchain_transactions(status);

CREATE INDEX IF NOT EXISTS idx_blockchain_transactions_hash
    ON blockchain_transactions(transaction_hash);

CREATE INDEX IF NOT EXISTS idx_treasury_withdrawals_status
    ON treasury_withdrawals(status);

CREATE INDEX IF NOT EXISTS idx_treasury_withdrawals_order
    ON treasury_withdrawals(order_id);

CREATE INDEX IF NOT EXISTS idx_pagar_webhook_events_payment
    ON pagar_webhook_events(payment_id);

CREATE INDEX IF NOT EXISTS idx_pagar_webhook_events_created
    ON pagar_webhook_events(created_at DESC);

CREATE INDEX IF NOT EXISTS idx_financial_operations_status
    ON financial_operations(status);


-- ============================================================
-- 19. REGRAS DE SEGURANÇA CONTRA DUPLICAÇÃO
-- ============================================================

CREATE UNIQUE INDEX IF NOT EXISTS ux_orders_pagar_payment_id
    ON orders(pagar_payment_id)
    WHERE pagar_payment_id IS NOT NULL;

CREATE UNIQUE INDEX IF NOT EXISTS ux_orders_transaction_hash
    ON orders(transaction_hash)
    WHERE transaction_hash IS NOT NULL;


-- ============================================================
-- 20. VISTA DA LIQUIDEZ INTERNA
-- ============================================================
-- NÃO substitui a leitura da blockchain.
-- A blockchain continua sendo a fonte do saldo real.
--
-- available = on-chain - reserved
-- ============================================================

CREATE OR REPLACE VIEW treasury_liquidity AS
SELECT
    id,
    mzn_balance,
    usdt_onchain_balance,
    trx_onchain_balance,
    usdt_reserved,
    mzn_reserved,

    GREATEST(
        usdt_onchain_balance - usdt_reserved,
        0
    ) AS usdt_available,

    GREATEST(
        mzn_balance - mzn_reserved,
        0
    ) AS mzn_available,

    last_blockchain_sync_at,
    last_financial_sync_at,
    updated_at

FROM treasury_wallet
WHERE id = 1;


-- ============================================================
-- FIM DA ESTRUTURA FINANCEIRA USDTMZ
-- ============================================================
