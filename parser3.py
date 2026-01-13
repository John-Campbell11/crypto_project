import psycopg2
from psycopg2.extras import execute_batch
import struct
import hashlib

# --- Configuration ---
OBFUSCATION_KEY = bytes.fromhex("5ac1d292e7350efe")
KEY_LENGTH = len(OBFUSCATION_KEY)
BATCH_SIZE = 1000  # Commit every 1000 blocks

def get_db_connection():
    try:
        return psycopg2.connect(
            dbname="bitcoin_0",
            user="john",
            password="john",
            host="localhost",
            port=5432
        )
    except psycopg2.Error as e:
        print(f"Error connecting to database: {e}")
        raise

def deobfuscate_stream(data: bytes, key_offset: int) -> bytes:
    return bytes(data[i] ^ OBFUSCATION_KEY[(key_offset + i) % KEY_LENGTH] for i in range(len(data)))

def read_varint_from_buffer(data, offset):
    prefix = data[offset]
    if prefix < 0xfd:
        return prefix, 1
    elif prefix == 0xfd:
        return int.from_bytes(data[offset + 1:offset + 3], "little"), 3
    elif prefix == 0xfe:
        return int.from_bytes(data[offset + 1:offset + 5], "little"), 5
    else:
        return int.from_bytes(data[offset + 1:offset + 9], "little"), 9

def double_sha256(data: bytes) -> bytes:
    return hashlib.sha256(hashlib.sha256(data).digest()).digest()

def parse_transaction(data: bytes, offset: int):
    start_offset = offset
    version = struct.unpack("<I", data[offset:offset + 4])[0]
    offset += 4

    input_count, varint_size = read_varint_from_buffer(data, offset)
    offset += varint_size

    inputs = []
    for _ in range(input_count):
        prev_hash = data[offset:offset + 32]
        offset += 32
        prev_index = struct.unpack("<I", data[offset:offset + 4])[0]
        offset += 4
        script_len, varint_size = read_varint_from_buffer(data, offset)
        offset += varint_size
        script_sig = data[offset:offset + script_len]
        offset += script_len
        sequence = struct.unpack("<I", data[offset:offset + 4])[0]
        offset += 4
        inputs.append({
            'prev_hash': prev_hash,
            'prev_index': prev_index,
            'script_sig': script_sig,
            'sequence': sequence
        })

    output_count, varint_size = read_varint_from_buffer(data, offset)
    offset += varint_size

    outputs = []
    for _ in range(output_count):
        value = struct.unpack("<Q", data[offset:offset + 8])[0]
        offset += 8
        script_len, varint_size = read_varint_from_buffer(data, offset)
        offset += varint_size
        script_pubkey = data[offset:offset + script_len]
        offset += script_len
        outputs.append({'value': value, 'script_pubkey': script_pubkey})

    locktime = struct.unpack("<I", data[offset:offset + 4])[0]
    offset += 4

    tx_data = data[start_offset:offset]
    txid = double_sha256(tx_data)[::-1]  # Reverse for display

    is_coinbase = (inputs[0]['prev_hash'] == b'\x00' * 32 and inputs[0]['prev_index'] == 0xFFFFFFFF)

    return {
        'txid': txid,
        'version': version,
        'inputs': inputs,
        'outputs': outputs,
        'locktime': locktime,
        'is_coinbase': is_coinbase
    }, offset - start_offset

def read_all_blocks_to_sql(dat_path: str):
    conn = get_db_connection()
    cursor = conn.cursor()

    file_position = 0
    blocks_batch = []
    txs_batch = []
    outputs_batch = []
    inputs_batch = []

    total_blocks = 0

    with open(dat_path, 'rb') as f:
        while True:
            magic_encrypted = f.read(4)
            if len(magic_encrypted) < 4:
                break
            magic = deobfuscate_stream(magic_encrypted, file_position)
            file_position += 4

            size_encrypted = f.read(4)
            if len(size_encrypted) < 4:
                break
            size_bytes = deobfuscate_stream(size_encrypted, file_position)
            block_size = struct.unpack("<I", size_bytes)[0]
            file_position += 4

            block_data_encrypted = f.read(block_size)
            if len(block_data_encrypted) < block_size:
                break
            block_data = deobfuscate_stream(block_data_encrypted, file_position)
            file_position += block_size

            header = block_data[:80]
            block_hash = double_sha256(header)[::-1]
            timestamp = struct.unpack("<I", header[68:72])[0]

            blocks_batch.append((block_hash, timestamp, False))
            total_blocks += 1

            offset = 80
            tx_count, varint_size = read_varint_from_buffer(block_data, offset)
            offset += varint_size

            for _ in range(tx_count):
                tx, tx_size = parse_transaction(block_data, offset)
                offset += tx_size

                txs_batch.append((tx['txid'], block_hash, tx['is_coinbase']))

                for vout, out in enumerate(tx['outputs']):
                    outputs_batch.append((tx['txid'], vout, out['value'], out['script_pubkey'], False))

                for vin, inp in enumerate(tx['inputs']):
                    if tx['is_coinbase']:
                        inputs_batch.append((tx['txid'], vin, None, None, inp['script_sig']))
                    else:
                        inputs_batch.append((tx['txid'], vin, inp['prev_hash'][::-1], inp['prev_index'], inp['script_sig']))

            if len(blocks_batch) >= BATCH_SIZE:
                execute_batch(cursor,
                    "INSERT INTO blocks (hash, timestamp, orphaned) VALUES (%s, %s, %s) ON CONFLICT (hash) DO NOTHING",
                    blocks_batch
                )
                execute_batch(cursor,
                    "INSERT INTO transactions (txid, block_hash, is_coinbase) VALUES (%s, %s, %s) ON CONFLICT (txid) DO NOTHING",
                    txs_batch
                )
                execute_batch(cursor,
                    "INSERT INTO outputs (txid, vout, value, script_pubkey, spent) VALUES (%s, %s, %s, %s, %s) ON CONFLICT (txid, vout) DO NOTHING",
                    outputs_batch
                )
                execute_batch(cursor,
                    "INSERT INTO inputs (txid, vin, prev_txid, prev_vout, script_sig) VALUES (%s, %s, %s, %s, %s) ON CONFLICT (txid, vin) DO NOTHING",
                    inputs_batch
                )
                conn.commit()
                print(f"[{total_blocks}] Blocks processed, offset {file_position} bytes...")
                blocks_batch.clear()
                txs_batch.clear()
                outputs_batch.clear()
                inputs_batch.clear()

    # Insert any remaining batches
    if blocks_batch:
        execute_batch(cursor,
            "INSERT INTO blocks (hash, timestamp, orphaned) VALUES (%s, %s, %s) ON CONFLICT (hash) DO NOTHING",
            blocks_batch
        )
        execute_batch(cursor,
            "INSERT INTO transactions (txid, block_hash, is_coinbase) VALUES (%s, %s, %s) ON CONFLICT (txid) DO NOTHING",
            txs_batch
        )
        execute_batch(cursor,
            "INSERT INTO outputs (txid, vout, value, script_pubkey, spent) VALUES (%s, %s, %s, %s, %s) ON CONFLICT (txid, vout) DO NOTHING",
            outputs_batch
        )
        execute_batch(cursor,
            "INSERT INTO inputs (txid, vin, prev_txid, prev_vout, script_sig) VALUES (%s, %s, %s, %s, %s) ON CONFLICT (txid, vin) DO NOTHING",
            inputs_batch
        )
        conn.commit()
        print(f"Final batch committed. Total blocks processed: {total_blocks}")

    cursor.close()
    conn.close()
    print("Finished importing all blocks.")

if __name__ == "__main__":
    dat_file = "/home/btc-user/.bitcoin/blocks/blk00000.dat"
    read_all_blocks_to_sql(dat_file)
