-- ============================================================================
-- Targeted Validation Script
-- Block: 0000000000000000000297b3c2fd6c811acaa82f56e7ee40b01eaf5bee5e80b9
-- TXID : 0000000023b9add126f9d7b1313aa73668375f8014f1fb4d9b38bad1935c782a
-- Any returned rows indicate a data integrity error.
-- ============================================================================

-- ----------------------------
-- 1. Block must exist
-- ----------------------------
SELECT 'BLOCK_MISSING' AS error
WHERE NOT EXISTS (
    SELECT 1 FROM blocks
    WHERE hash = decode('0000000000000000000297b3c2fd6c811acaa82f56e7ee40b01eaf5bee5e80b9', 'hex')
      AND orphaned = FALSE
);

-- ----------------------------
-- 2. Transaction must exist in this block
-- ----------------------------
SELECT 'TX_MISSING_OR_WRONG_BLOCK' AS error
WHERE NOT EXISTS (
    SELECT 1
    FROM transactions
    WHERE txid = decode('0000000023b9add126f9d7b1313aa73668375f8014f1fb4d9b38bad1935c782a', 'hex')
      AND block_hash = decode('0000000000000000000297b3c2fd6c811acaa82f56e7ee40b01eaf5bee5e80b9', 'hex')
);

-- ----------------------------
-- 3. First output scriptPubKey must match
-- vout = 0
-- 5120b60ca3021624478539b8ba03462330224f409f3a91bc7313f05eaa6991645843
-- ----------------------------
SELECT 'OUTPUT_0_SCRIPT_MISMATCH' AS error, o.txid, o.vout, encode(o.script_pubkey, 'hex') AS actual_script
FROM outputs o
WHERE o.txid = decode('0000000023b9add126f9d7b1313aa73668375f8014f1fb4d9b38bad1935c782a', 'hex')
  AND o.vout = 0
  AND o.script_pubkey <> decode('5120b60ca3021624478539b8ba03462330224f409f3a91bc7313f05eaa6991645843', 'hex');

-- Missing output 0 entirely
SELECT 'OUTPUT_0_MISSING' AS error
WHERE NOT EXISTS (
    SELECT 1 FROM outputs
    WHERE txid = decode('0000000023b9add126f9d7b1313aa73668375f8014f1fb4d9b38bad1935c782a', 'hex')
      AND vout = 0
);

-- ----------------------------
-- 4. Second output scriptPubKey must match
-- vout = 1
-- 5120f69f0883243057b4cac41bbcc49f4f045092935cf10b78cd0b790e0afc05c9db
-- ----------------------------
SELECT 'OUTPUT_1_SCRIPT_MISMATCH' AS error, o.txid, o.vout, encode(o.script_pubkey, 'hex') AS actual_script
FROM outputs o
WHERE o.txid = decode('0000000023b9add126f9d7b1313aa73668375f8014f1fb4d9b38bad1935c782a', 'hex')
  AND o.vout = 1
  AND o.script_pubkey <> decode('5120f69f0883243057b4cac41bbcc49f4f045092935cf10b78cd0b790e0afc05c9db', 'hex');

-- Missing output 1 entirely
SELECT 'OUTPUT_1_MISSING' AS error
WHERE NOT EXISTS (
    SELECT 1 FROM outputs
    WHERE txid = decode('0000000023b9add126f9d7b1313aa73668375f8014f1fb4d9b38bad1935c782a', 'hex')
      AND vout = 1
);

-- ----------------------------
-- 5. Input must reference correct prev tx + vout
-- prev_txid = 00000000a03dbe7788988f9d9495ad4ed877c54202c374ec2f11d18a3e941f18
-- prev_vout = 1
-- ----------------------------
SELECT 'INPUT_PREVOUT_MISMATCH' AS error, i.txid, i.vin, encode(i.prev_txid, 'hex') AS actual_prev_txid, i.prev_vout
FROM inputs i
WHERE i.txid = decode('0000000023b9add126f9d7b1313aa73668375f8014f1fb4d9b38bad1935c782a', 'hex')
  AND NOT (
      i.prev_txid = decode('00000000a03dbe7788988f9d9495ad4ed877c54202c374ec2f11d18a3e941f18', 'hex')
      AND i.prev_vout = 1
  );

-- Missing expected input entirely
SELECT 'INPUT_MISSING' AS error
WHERE NOT EXISTS (
    SELECT 1 FROM inputs
    WHERE txid = decode('0000000023b9add126f9d7b1313aa73668375f8014f1fb4d9b38bad1935c782a', 'hex')
      AND prev_txid = decode('00000000a03dbe7788988f9d9495ad4ed877c54202c374ec2f11d18a3e941f18', 'hex')
      AND prev_vout = 1
);

-- ----------------------------
-- 6. Sanity: TX must have exactly 1 input and 2 outputs
-- ----------------------------
SELECT 'UNEXPECTED_INPUT_COUNT' AS error, COUNT(*) AS input_count
FROM inputs
WHERE txid = decode('0000000023b9add126f9d7b1313aa73668375f8014f1fb4d9b38bad1935c782a', 'hex')
HAVING COUNT(*) <> 1;

SELECT 'UNEXPECTED_OUTPUT_COUNT' AS error, COUNT(*) AS output_count
FROM outputs
WHERE txid = decode('0000000023b9add126f9d7b1313aa73668375f8014f1fb4d9b38bad1935c782a', 'hex')
HAVING COUNT(*) <> 2;

