import psycopg2
from psycopg2.extras import execute_values
import struct
import hashlib
import glob
import os
import mmap

# --- Configuration ---
OBFUSCATION_KEY = bytes.fromhex("5ac1d292e7350efe")
KEY_LENGTH = len(OBFUSCATION_KEY)
BATCH_SIZE = 10000
DAT_DIR = "/home/btc-user/.bitcoin/blocks/"

# --- DB Connection ---
def get_db_connection():
    conn = psycopg2.connect(
        dbname="bitcoin_proto",
        user="john",
        password="john",
        host="localhost",
        port=5432
    )
    # Optimize session for bulk insert
    cur = conn.cursor()
    cur.execute("SET synchronous_commit TO OFF")
    cur.execute("SET work_mem TO '256MB'")
    cur.execute("SET maintenance_work_mem TO '1GB'")
    cur.close()
    return conn

# --- Helpers ---
def deobfuscate_stream(data: bytes, key_offset: int) -> bytearray:
    """XOR deobfuscation for block data"""
    result = bytearray(len(data))
    key_idx = key_offset % KEY_LENGTH
    for i in range(len(data)):
        result[i] = data[i] ^ OBFUSCATION_KEY[key_idx]
        key_idx = (key_idx + 1) % KEY_LENGTH
    return result

def read_varint_fast(data, offset):
    """Fast varint reader"""
    prefix = data[offset]
    if prefix < 0xfd:
        return prefix, 1
    elif prefix == 0xfd:
        return data[offset+1] | (data[offset+2] << 8), 3
    elif prefix == 0xfe:
        return (data[offset+1] | (data[offset+2] << 8) |
                (data[offset+3] << 16) | (data[offset+4] << 24)), 5
    else:
        return int.from_bytes(data[offset+1:offset+9], "little"), 9

def double_sha256(data: bytes) -> bytes:
    return hashlib.sha256(hashlib.sha256(data).digest()).digest()

def get_script_type_fast(script_pubkey: bytes) -> str:
    """Fast script type detection"""
    l = len(script_pubkey)
    if l == 25 and script_pubkey[:2] == b'\x76\xa9' and script_pubkey[-2:] == b'\x88\xac':
        return "P2PKH"
    if l == 23 and script_pubkey[0] == 0xa9 and script_pubkey[-1] == 0x87:
        return "P2SH"
    if l == 22 and script_pubkey[:2] == b'\x00\x14':
        return "P2WPKH"
    if l == 34 and script_pubkey[:2] == b'\x00\x20':
        return "P2WSH"
    if l == 34 and script_pubkey[:2] == b'\x51\x20':
        return "P2TR"
    if script_pubkey and script_pubkey[0] == 0x6a:
        return "OP_RETURN"
    return "unknown"

def parse_transaction_fast(data: memoryview, offset: int):
    """Parse a transaction and return structured data"""
    start = offset
    version = struct.unpack_from("<I", data, offset)[0]
    offset += 4

    segwit = False
    if data[offset] == 0x00 and data[offset+1] == 0x01:
        segwit = True
        offset += 2

    body_start = offset

    # Inputs
    input_count, size = read_varint_fast(data, offset)
    offset += size
    inputs = []
    for _ in range(input_count):
        prev_hash = bytes(data[offset:offset+32])
        offset += 32
        prev_index = struct.unpack_from("<I", data, offset)[0]
        offset += 4
        script_len, size = read_varint_fast(data, offset)
        offset += size
        offset += script_len
        sequence = struct.unpack_from("<I", data, offset)[0]
        offset += 4
        inputs.append((prev_hash, prev_index, sequence))

    # Outputs
    output_count, size = read_varint_fast(data, offset)
    offset += size
    outputs = []
    for _ in range(output_count):
        value = struct.unpack_from("<Q", data, offset)[0]
        offset += 8
        script_len, size = read_varint_fast(data, offset)
        offset += size
        script_pubkey = bytes(data[offset:offset+script_len])
        offset += script_len
        outputs.append((value, script_pubkey))

    body_end = offset

    # Witness
    if segwit:
        for _ in range(input_count):
            wit_count, size = read_varint_fast(data, offset)
            offset += size
            for _ in range(wit_count):
                item_len, size = read_varint_fast(data, offset)
                offset += size + item_len

    # Locktime
    locktime = struct.unpack_from("<I", data, offset)[0]
    offset += 4

    # TXID
    legacy_data = bytes(data[start:start+4]) + bytes(data[body_start:body_end]) + bytes(data[offset-4:offset])
    txid = double_sha256(legacy_data)[::-1]

    # Coinbase check
    is_coinbase = inputs[0][0] == b'\x00'*32 and inputs[0][1] == 0xFFFFFFFF

    return (txid, version, inputs, outputs, locktime, is_coinbase, segwit), offset - start

# --- Bulk insert using optimized execute_values ---
def bulk_insert_fast(cursor, blocks, txs, outputs, inputs):
    """Optimized execute_values bulk insert for large batches of binary data"""

    if blocks:
        execute_values(
            cursor,
            """
            INSERT INTO blocks (hash, previous_block, timestamp, orphaned)
            VALUES %s
            ON CONFLICT (hash) DO NOTHING
            """,
            blocks,
            template="(%s, %s, %s, %s)"
        )

    if txs:
        execute_values(
            cursor,
            """
            INSERT INTO transactions (txid, block_hash, is_coinbase)
            VALUES %s
            ON CONFLICT (txid) DO NOTHING
            """,
            txs,
            template="(%s, %s, %s)"
        )

    if outputs:
        execute_values(
            cursor,
            """
            INSERT INTO outputs (txid, vout, value, script_pubkey, script_type)
            VALUES %s
            ON CONFLICT (txid, vout) DO NOTHING
            """,
            outputs,
            template="(%s, %s, %s, %s, %s)"
        )

    if inputs:
        execute_values(
            cursor,
            """
            INSERT INTO inputs (txid, vin, prev_txid, prev_vout)
            VALUES %s
            ON CONFLICT (txid, vin) DO NOTHING
            """,
            inputs,
            template="(%s, %s, %s, %s)"
        )

# --- Process a .dat file ---
def process_dat_file_fast(fpath, conn):
    cursor = conn.cursor()
    file_pos = 0
    blocks_batch, txs_batch, outputs_batch, inputs_batch = [], [], [], []
    total_blocks = 0

    with open(fpath, 'rb') as f:
        with mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as mmapped_file:
            file_size = len(mmapped_file)

            while file_pos < file_size - 8:
                # Magic & size
                magic_enc = mmapped_file[file_pos:file_pos+4]
                magic = deobfuscate_stream(magic_enc, file_pos)
                file_pos += 4

                size_enc = mmapped_file[file_pos:file_pos+4]
                size_bytes = deobfuscate_stream(size_enc, file_pos)
                block_size = struct.unpack("<I", bytes(size_bytes))[0]
                file_pos += 4

                if file_pos + block_size > file_size:
                    break

                block_data = deobfuscate_stream(mmapped_file[file_pos:file_pos+block_size], file_pos)
                file_pos += block_size

                # Block header
                header = block_data[:80]
                block_hash = double_sha256(header)[::-1]
                prev_block = header[4:36][::-1]
                timestamp = struct.unpack("<I", header[68:72])[0]
                blocks_batch.append((block_hash, prev_block, timestamp, False))
                total_blocks += 1

                block_view = memoryview(block_data)
                offset = 80
                tx_count, size = read_varint_fast(block_view, offset)
                offset += size

                for _ in range(tx_count):
                    tx, tx_size = parse_transaction_fast(block_view, offset)
                    offset += tx_size

                    txid, version, inputs, outputs, locktime, is_coinbase, segwit = tx
                    txs_batch.append((txid, block_hash, is_coinbase))

                    for vout, (value, script_pubkey) in enumerate(outputs):
                        script_type = get_script_type_fast(script_pubkey)
                        outputs_batch.append((txid, vout, value, script_pubkey, script_type))

                    for vin, (prev_hash, prev_index, sequence) in enumerate(inputs):
                        prev_txid = prev_hash[::-1] if not is_coinbase else None
                        prev_vout = prev_index if not is_coinbase else None
                        inputs_batch.append((txid, vin, prev_txid, prev_vout))

                if len(blocks_batch) >= BATCH_SIZE:
                    bulk_insert_fast(cursor, blocks_batch, txs_batch, outputs_batch, inputs_batch)
                    conn.commit()
                    blocks_batch.clear()
                    txs_batch.clear()
                    outputs_batch.clear()
                    inputs_batch.clear()

    if blocks_batch:
        bulk_insert_fast(cursor, blocks_batch, txs_batch, outputs_batch, inputs_batch)
        conn.commit()

    cursor.close()
    return total_blocks

# --- Main ---
def main():
    dat_files = sorted(glob.glob(os.path.join(DAT_DIR, "blk*.dat")))[3500:3501]  # Adjust as needed
    conn = get_db_connection()
    total_blocks = 0

    for fpath in dat_files:
        print(f"Processing {fpath}...")
        blocks_in_file = process_dat_file_fast(fpath, conn)
        total_blocks += blocks_in_file
        print(f"Finished {fpath}, {blocks_in_file} blocks added. Total so far: {total_blocks}")

    conn.close()
    print(f"Done. Total blocks imported: {total_blocks}")

if __name__ == "__main__":
    main()

