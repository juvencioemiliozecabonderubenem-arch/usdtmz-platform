-- ============================================
-- USDTMZ — ESTRUTURA INICIAL DA BASE DE DADOS
-- ============================================

-- UTILIZADORES
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


-- CARTEIRAS DOS UTILIZADORES
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


-- PEDIDOS DE COMPRA DE USDT
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


-- LEVANTAMENTOS
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


-- HISTÓRICO DE MOVIMENTAÇÕES
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


-- LOG DE AÇÕES ADMINISTRATIVAS
CREATE TABLE IF NOT EXISTS admin_audit_logs (
    id BIGSERIAL PRIMARY KEY,

    admin_id VARCHAR(100) NOT NULL,

    action VARCHAR(100) NOT NULL,

    entity_type VARCHAR(50),

    entity_id BIGINT,

    details JSONB,

    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);


-- ÍNDICES
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

CREATE INDEX IF NOT EXISTS idx_transactions_user_id
    ON transactions(user_id);

CREATE INDEX IF NOT EXISTS idx_admin_audit_logs_created_at
    ON admin_audit_logs(created_at);


-- ============================================
-- FIM DA ESTRUTURA USDTMZ
-- ============================================
