-- 1. BLOCKCHAIN LAYER (Optimized for Reorgs)
---------------------------------------------------------

CREATE TABLE blocks (
    hash            BYTEA PRIMARY KEY,
    previous_block  BYTEA,              -- From new schema (essential for canonical ordering)
    timestamp       BIGINT NOT NULL,    -- From old schema (more efficient for raw unix timestamps)
    orphaned        BOOLEAN DEFAULT FALSE -- From old schema (crucial for handling reorgs)
);

CREATE TABLE transactions (
    txid            BYTEA PRIMARY KEY,
    block_hash      BYTEA NOT NULL REFERENCES blocks(hash),
    is_coinbase     BOOLEAN NOT NULL DEFAULT FALSE
);

CREATE TABLE inputs (
    txid            BYTEA NOT NULL REFERENCES transactions(txid),
    vin             INTEGER NOT NULL,
    prev_txid       BYTEA,              -- NULL for coinbase
    prev_vout       INTEGER,            -- NULL for coinbase
    script_sig      BYTEA,
    PRIMARY KEY (txid, vin),
    FOREIGN KEY (prev_txid, prev_vout) 
);

CREATE TABLE outputs (
    txid            BYTEA NOT NULL REFERENCES transactions(txid),
    vout            INTEGER NOT NULL,
    value           BIGINT NOT NULL,    -- In Satoshis
    script_pubkey   BYTEA NOT NULL,
    script_type     TEXT,               -- From new schema (needed for SegWit/P2SH derivation)
    spent           BOOLEAN DEFAULT FALSE,
    spent_txid      BYTEA REFERENCES transactions(txid), -- Linkage for fast forward-tracing
    PRIMARY KEY (txid, vout)
);

---------------------------------------------------------
-- 2. FORENSIC & ENTITY LAYER (Wallet Clustering)
---------------------------------------------------------

CREATE TABLE wallets (
    wallet_id       SERIAL PRIMARY KEY
);

CREATE TABLE wallet_addresses (
    wallet_id       INT REFERENCES wallets(wallet_id),
    address         TEXT NOT NULL,      
    script_type     TEXT NOT NULL,
    PRIMARY KEY (wallet_id, address)
);

---------------------------------------------------------
-- 3. LEGAL TRACING LAYER (LIBR & Seizure Mapping)
---------------------------------------------------------

CREATE TABLE wallet_transactions (
    wallet_id       INT REFERENCES wallets(wallet_id),
    txid            BYTEA REFERENCES transactions(txid),
    direction       TEXT NOT NULL,      -- 'in' or 'out'
    value           BIGINT NOT NULL,
    ts              BIGINT NOT NULL,    -- Synced with blocks.timestamp
    PRIMARY KEY (wallet_id, txid, direction)
);

CREATE TABLE wallet_balances (
    wallet_id       INT REFERENCES wallets(wallet_id),
    ts              BIGINT NOT NULL,
    total_balance   BIGINT NOT NULL,
    proceeds_balance BIGINT DEFAULT 0,  -- Tracking SUA proceeds
    PRIMARY KEY (wallet_id, ts)
);

---------------------------------------------------------
-- 4. THE "BEST OF BOTH" INDEXING STRATEGY
---------------------------------------------------------

-- Fast UTXO Lookups (from old schema)
CREATE INDEX idx_inputs_prevout ON inputs(prev_txid, prev_vout);

-- Fast Forward-Tracing (from new schema)
CREATE INDEX idx_outputs_spent_txid ON outputs(spent_txid) WHERE spent_txid IS NOT NULL;

-- Time-resolved Balance queries (Critical for LIBR)
CREATE INDEX idx_wallet_bal_ts ON wallet_balances(wallet_id, ts DESC);

-- Partial index for active UTXOs (Space efficient)
CREATE INDEX idx_outputs_utxo ON outputs(txid, vout) WHERE spent = FALSE;
