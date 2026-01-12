-- Blocks table: lightweight, just hash, timestamp, and orphan tracking
CREATE TABLE blocks (
    hash BYTEA PRIMARY KEY,
    timestamp BIGINT NOT NULL,
    orphaned BOOLEAN DEFAULT FALSE
);

-- Transactions table: links to blocks, flags coinbase transactions
CREATE TABLE transactions (
    txid BYTEA PRIMARY KEY,
    block_hash BYTEA NOT NULL REFERENCES blocks(hash),
    is_coinbase BOOLEAN NOT NULL
);

-- Outputs table: stores all transaction outputs
CREATE TABLE outputs (
    txid BYTEA NOT NULL,
    vout INTEGER NOT NULL,
    value BIGINT NOT NULL,
    script_pubkey BYTEA NOT NULL,
    spent BOOLEAN DEFAULT FALSE,
    PRIMARY KEY (txid, vout)
);

-- Inputs table: references previous outputs being spent
CREATE TABLE inputs (
    txid BYTEA NOT NULL,
    vin INTEGER NOT NULL,
    prev_txid BYTEA,  -- NULL for coinbase inputs
    prev_vout INTEGER,  -- NULL for coinbase inputs
    script_sig BYTEA,
    PRIMARY KEY (txid, vin),
    FOREIGN KEY (prev_txid, prev_vout) REFERENCES outputs(txid, vout)
);

-- Index for fast UTXO lookups (which outputs are being spent)
CREATE INDEX idx_inputs_prevout ON inputs(prev_txid, prev_vout);

-- Index for handling chain reorganizations and block-transaction queries
CREATE INDEX idx_transactions_block ON transactions(block_hash);

-- Index for time-based block queries
CREATE INDEX idx_blocks_timestamp ON blocks(timestamp);

-- Index for finding unspent outputs
CREATE INDEX idx_outputs_spent ON outputs(spent) WHERE spent = FALSE;

-- Index for fetching all outputs of a transaction
CREATE INDEX idx_outputs_txid ON outputs(txid);
