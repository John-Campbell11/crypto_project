-- =====================================================
-- 1. BLOCKCHAIN LAYER (Optimized for Reorgs / Bulk Load)
-- =====================================================

-- Table to store blocks
CREATE TABLE blocks (
    hash            BYTEA PRIMARY KEY,        -- Block hash
    previous_block  BYTEA,                    -- Previous block hash for canonical ordering
    timestamp       BIGINT NOT NULL,          -- UNIX timestamp of the block
    orphaned        BOOLEAN DEFAULT FALSE     -- Marks dropped blocks after reorgs
);

-- Table to store transactions
CREATE TABLE transactions (
    txid            BYTEA PRIMARY KEY,        -- Transaction ID (hash)
    block_hash      BYTEA NOT NULL,           -- Block containing this transaction
    is_coinbase     BOOLEAN NOT NULL DEFAULT FALSE          -- Coinbase transaction flag
);

-- Table to store transaction outputs (UTXOs)
CREATE TABLE outputs (
    txid            BYTEA NOT NULL,           -- Parent transaction
    vout            INTEGER NOT NULL,         -- Output index
    value           BIGINT NOT NULL,          -- Amount in Satoshis
    script_pubkey   BYTEA NOT NULL,           -- Output script
    script_type     TEXT,                      -- Script type (e.g., P2PKH, P2SH, SegWit)
    PRIMARY KEY (txid, vout)
);

-- Table to store transaction inputs
CREATE TABLE inputs (
    txid            BYTEA NOT NULL,           -- Spending transaction
    vin             INTEGER NOT NULL,          -- Input index
    prev_txid       BYTEA,                     -- Previous transaction (NULL for coinbase)
    prev_vout       INTEGER,                   -- Previous output index (NULL for coinbase)
    PRIMARY KEY (txid, vin)
);

