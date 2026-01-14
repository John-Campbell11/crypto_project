import psycopg2
from psycopg2.extras import execute_values
import struct
import hashlib
import glob
import os

# --- Configuration ---
OBFUSCATION_KEY = bytes.fromhex("5ac1d292e7350efe")
KEY_LENGTH = len(OBFUSCATION_KEY)
BATCH_SIZE = 5000  # Adjust for memory / speed
DAT_DIR = "/home/btc-user/.bitcoin/blocks/"
MAX_FILES = 10

def get_db_connection():
    return psycopg2.connect(
        dbname="bitcoin_0",
        user="john",
        password="john",
        host="localhost",
        port=5432
    )

def deobfuscate_stream(data: bytes, key_offset: int) -> bytes:
    return bytes(data[i] ^ OBFUSCATION_KEY[(key_offset + i) % KEY_LENGTH] for i in range(len(data)))

def read_varint(data, offset):
    prefix = data[offset]
    if prefix < 0xfd:
        return prefix, 1
    elif prefix == 0xfd:
        return int.from_bytes(data[offset+1:offset+3], "little"), 3
    elif prefix == 0xfe:
        return int.from_bytes(data[offset+1:offset+5], "little"), 5
    else:
        return int.from_bytes(data[offset+1:offset+9], "little"), 9

def double_sha256(data: bytes) -> bytes:
    return hashlib.sha256(hashlib.sha256(data).digest()).digest()

# --- Script type detection ---
def get_script_type(script_pubkey: bytes) -> str:
    if len(script_pubkey) == 25 and script_pubkey[0] == 0x76 and script_pubkey[1] == 0xa9 and script_pubkey[-2] == 0x88 and script_pubkey[-1] == 0xac:
        return "P2PKH"
    elif len(script_pubkey) == 23 and script_pubkey[0] == 0xa9 and script_pubkey[-1] == 0x87:
        return "P2SH"
    elif len(script_pubkey) in [22, 34] and script_pubkey[0] == 0x00:
        return "P2WPKH/P2WSH"
    else:
        return "unknown"

def parse_transaction(data: bytes, offset: int):
    start = offset
    version = struct.unpack("<I", data[offset:offset+4])[0]
    offset += 4

    segwit = False
    if data[offset] == 0x00 and data[offset+1] == 0x01:
        segwit = True
        offset += 2  # skip marker + flag

    input_count, size = read_varint(data, offset)
    offset += size

    inputs = []
    for _ in range(input_count):
        prev_hash = data[offset:offset+32]
        offset += 32
        prev_index = struct.unpack("<I", data[offset:offset+4])[0]
        offset += 4
        script_len, size = read_varint(data, offset)
        offset += size
        script_sig = data[offset:offset+script_len]
        offset += script_len
        sequence = struct.unpack("<I", data[offset:offset+4])[0]
        offset += 4
        inputs.append({'prev_hash': prev_hash, 'prev_index': prev_index, 'script_sig': script_sig, 'sequence': sequence})

    output_count, size = read_varint(data, offset)
    offset += size

    outputs = []
    for _ in range(output_count):
        value = struct.unpack("<Q", data[offset:offset+8])[0]
        offset += 8
        script_len, size = read_varint(data, offset)
        offset += size
        script_pubkey = data[offset:offset+script_len]
        offset += script_len
        outputs.append({'value': value, 'script_pubkey': script_pubkey})

    # SegWit: skip witness
    if segwit:
        for inp in inputs:
            wit_count, size = read_varint(data, offset)
            offset += size
            for _ in range(wit_count):
                item_len, size = read_varint(data, offset)
                offset += size + item_len

    locktime = struct.unpack("<I", data[offset:offset+4])[0]
    offset += 4

    # Compute txid without witness
    tx_end = offset
    if segwit:
        # txid ignores marker+flag+wit
        non_wit_tx = data[start:offset]
        # remove marker + flag
        non_wit_tx = data[start:start+4] + data[start+6:offset]
        txid = double_sha256(non_wit_tx)[::-1]
    else:
        txid = double_sha256(data[start:tx_end])[::-1]

    is_coinbase = (inputs[0]['prev_hash'] == b'\x00'*32 and inputs[0]['prev_index'] == 0xFFFFFFFF)
    return {'txid': txid, 'version': version, 'inputs': inputs, 'outputs': outputs, 'locktime': locktime, 'is_coinbase': is_coinbase}, tx_end-start

def bulk_insert(cursor, blocks, txs, outputs, inputs):
    execute_values(cursor,
        "INSERT INTO blocks (hash, previous_block, timestamp, orphaned) VALUES %s ON CONFLICT (hash) DO NOTHING",
        blocks
    )
    execute_values(cursor,
        "INSERT INTO transactions (txid, block_hash, is_coinbase) VALUES %s ON CONFLICT (txid) DO NOTHING",
        txs
    )
    execute_values(cursor,
        "INSERT INTO outputs (txid, vout, value, script_pubkey, script_type, spent) VALUES %s ON CONFLICT (txid, vout) DO NOTHING",
        outputs
    )
    execute_values(cursor,
        "INSERT INTO inputs (txid, vin, prev_txid, prev_vout, script_sig) VALUES %s ON CONFLICT (txid, vin) DO NOTHING",
        inputs
    )

def process_dat_file(fpath, conn):
    cursor = conn.cursor()
    file_pos = 0
    blocks_batch, txs_batch, outputs_batch, inputs_batch = [], [], [], []
    total_blocks = 0

    with open(fpath, 'rb') as f:
        while True:
            magic_encrypted = f.read(4)
            if len(magic_encrypted) < 4: break
            magic = deobfuscate_stream(magic_encrypted, file_pos)
            file_pos += 4

            size_encrypted = f.read(4)
            if len(size_encrypted) < 4: break
            size_bytes = deobfuscate_stream(size_encrypted, file_pos)
            block_size = struct.unpack("<I", size_bytes)[0]
            file_pos += 4

            block_data_enc = f.read(block_size)
            if len(block_data_enc) < block_size: break
            block_data = deobfuscate_stream(block_data_enc, file_pos)
            file_pos += block_size

            header = block_data[:80]
            block_hash = double_sha256(header)[::-1]
            prev_block = header[4:36][::-1]
            timestamp = struct.unpack("<I", header[68:72])[0]

            blocks_batch.append((block_hash, prev_block, timestamp, False))
            total_blocks += 1

            offset = 80
            tx_count, size = read_varint(block_data, offset)
            offset += size

            for _ in range(tx_count):
                tx, tx_size = parse_transaction(block_data, offset)
                offset += tx_size

                txs_batch.append((tx['txid'], block_hash, tx['is_coinbase']))

                for vout, out in enumerate(tx['outputs']):
                    script_type = get_script_type(out['script_pubkey'])
                    outputs_batch.append((tx['txid'], vout, out['value'], out['script_pubkey'], script_type, False))

                for vin, inp in enumerate(tx['inputs']):
                    if tx['is_coinbase']:
                        inputs_batch.append((tx['txid'], vin, None, None, inp['script_sig']))
                    else:
                        inputs_batch.append((tx['txid'], vin, inp['prev_hash'][::-1], inp['prev_index'], inp['script_sig']))

            if len(blocks_batch) >= BATCH_SIZE:
                bulk_insert(cursor, blocks_batch, txs_batch, outputs_batch, inputs_batch)
                conn.commit()
                blocks_batch.clear()
                txs_batch.clear()
                outputs_batch.clear()
                inputs_batch.clear()

    if blocks_batch:
        bulk_insert(cursor, blocks_batch, txs_batch, outputs_batch, inputs_batch)
        conn.commit()
    cursor.close()
    return total_blocks

def main():
    dat_files = sorted(glob.glob(os.path.join(DAT_DIR, "blk*.dat")))[:MAX_FILES]
    conn = get_db_connection()
    total_blocks = 0

    for fpath in dat_files:
        print(f"Processing {fpath}...")
        blocks_in_file = process_dat_file(fpath, conn)
        total_blocks += blocks_in_file
        print(f"Finished {fpath}, {blocks_in_file} blocks added. Total so far: {total_blocks}")

    conn.close()
    print(f"Done. Total blocks imported: {total_blocks}")

if __name__ == "__main__":
    main()

