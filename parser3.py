import psycopg2
from psycopg2.extras import execute_batch
import struct
import hashlib
from pathlib import Path

# --- Configuration: The Obfuscation Key (This is the FIXED file-wide key) ---
# The key provided by the user: 5ac1d292e7350efe (64-bit/8-byte key)
OBFUSCATION_KEY = bytes.fromhex("5ac1d292e7350efe")
KEY_LENGTH = len(OBFUSCATION_KEY)

def get_db_connection():
    """
    Connects to the PostgreSQL database bitcoin_0 owned by john with no password.
    """
    try:
        conn = psycopg2.connect(
            dbname="bitcoin_0",
            user="john",
            password="",
            host="localhost",
            port=5432
        )
        return conn
    except psycopg2.Error as e:
        print(f"Error connecting to database: {e}")
        raise

def deobsfucate_stream(data: bytes, key_offset: int) -> bytes:
    """
    Applies a repeating XOR key to the data stream, starting the key application 
    at a specific offset determined by the total file position.
    """
    decrypted = bytearray(len(data))
    for i in range(len(data)):
        # Calculate the correct key index based on the stream's current position
        key_index = (key_offset + i) % KEY_LENGTH
        decrypted[i] = data[i] ^ OBFUSCATION_KEY[key_index]
    return bytes(decrypted)

def read_varint_from_buffer(data, offset):
    """Helper to read VarInt from a bytes buffer without file operations."""
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
    """Calculate double SHA256 hash (used for block and transaction hashes)."""
    return hashlib.sha256(hashlib.sha256(data).digest()).digest()

def parse_transaction(data: bytes, offset: int):
    """
    Parse a single transaction from the data buffer.
    Returns: (tx_dict, bytes_consumed)
    """
    start_offset = offset
    
    # Version (4 bytes)
    version = struct.unpack("<I", data[offset:offset + 4])[0]
    offset += 4
    
    # Input count (VarInt)
    input_count, varint_size = read_varint_from_buffer(data, offset)
    offset += varint_size
    
    inputs = []
    for _ in range(input_count):
        # Previous output hash (32 bytes)
        prev_hash = data[offset:offset + 32]
        offset += 32
        
        # Previous output index (4 bytes)
        prev_index = struct.unpack("<I", data[offset:offset + 4])[0]
        offset += 4
        
        # Script length (VarInt)
        script_len, varint_size = read_varint_from_buffer(data, offset)
        offset += varint_size
        
        # Script
        script_sig = data[offset:offset + script_len]
        offset += script_len
        
        # Sequence (4 bytes)
        sequence = struct.unpack("<I", data[offset:offset + 4])[0]
        offset += 4
        
        inputs.append({
            'prev_hash': prev_hash,
            'prev_index': prev_index,
            'script_sig': script_sig,
            'sequence': sequence
        })
    
    # Output count (VarInt)
    output_count, varint_size = read_varint_from_buffer(data, offset)
    offset += varint_size
    
    outputs = []
    for _ in range(output_count):
        # Value (8 bytes)
        value = struct.unpack("<Q", data[offset:offset + 8])[0]
        offset += 8
        
        # Script length (VarInt)
        script_len, varint_size = read_varint_from_buffer(data, offset)
        offset += varint_size
        
        # Script
        script_pubkey = data[offset:offset + script_len]
        offset += script_len
        
        outputs.append({
            'value': value,
            'script_pubkey': script_pubkey
        })
    
    # Locktime (4 bytes)
    locktime = struct.unpack("<I", data[offset:offset + 4])[0]
    offset += 4
    
    # Calculate transaction hash
    tx_data = data[start_offset:offset]
    txid = double_sha256(tx_data)
    
    # Check if coinbase (first input has null hash and index 0xFFFFFFFF)
    is_coinbase = (inputs[0]['prev_hash'] == b'\x00' * 32 and 
                   inputs[0]['prev_index'] == 0xFFFFFFFF)
    
    return {
        'txid': txid,
        'version': version,
        'inputs': inputs,
        'outputs': outputs,
        'locktime': locktime,
        'is_coinbase': is_coinbase
    }, offset - start_offset

def read_all_blocks_to_sql(dat_path: str):
    """
    Reads all blocks from a Bitcoin .dat file and inserts them into PostgreSQL.
    Returns a list of block hashes that were processed.
    """
    conn = get_db_connection()
    cursor = conn.cursor()
    
    block_hashes = []
    file_position = 0
    
    with open(dat_path, 'rb') as f:
        while True:
            # Read magic bytes (4 bytes)
            magic_encrypted = f.read(4)
            if len(magic_encrypted) < 4:
                break  # End of file
            
            magic = deobsfucate_stream(magic_encrypted, file_position)
            file_position += 4
            
            # Read block size (4 bytes)
            size_encrypted = f.read(4)
            if len(size_encrypted) < 4:
                break
            
            size_bytes = deobsfucate_stream(size_encrypted, file_position)
            block_size = struct.unpack("<I", size_bytes)[0]
            file_position += 4
            
            # Read block data
            block_data_encrypted = f.read(block_size)
            if len(block_data_encrypted) < block_size:
                break
            
            block_data = deobsfucate_stream(block_data_encrypted, file_position)
            file_position += block_size
            
            # Parse block header (80 bytes)
            header = block_data[:80]
            block_hash = double_sha256(header)
            
            # Extract timestamp from header (bytes 68-72)
            timestamp = struct.unpack("<I", header[68:72])[0]
            
            # Insert block
            cursor.execute(
                "INSERT INTO blocks (hash, timestamp, orphaned) VALUES (%s, %s, %s) "
                "ON CONFLICT (hash) DO NOTHING",
                (block_hash, timestamp, False)
            )
            
            # Parse transaction count
            offset = 80
            tx_count, varint_size = read_varint_from_buffer(block_data, offset)
            offset += varint_size
            
            # Parse each transaction
            for _ in range(tx_count):
                tx, tx_size = parse_transaction(block_data, offset)
                offset += tx_size
                
                # Insert transaction
                cursor.execute(
                    "INSERT INTO transactions (txid, block_hash, is_coinbase) "
                    "VALUES (%s, %s, %s) ON CONFLICT (txid) DO NOTHING",
                    (tx['txid'], block_hash, tx['is_coinbase'])
                )
                
                # Insert outputs
                output_data = [
                    (tx['txid'], vout, out['value'], out['script_pubkey'], False)
                    for vout, out in enumerate(tx['outputs'])
                ]
                execute_batch(
                    cursor,
                    "INSERT INTO outputs (txid, vout, value, script_pubkey, spent) "
                    "VALUES (%s, %s, %s, %s, %s) ON CONFLICT (txid, vout) DO NOTHING",
                    output_data
                )
                
                # Insert inputs
                input_data = []
                for vin, inp in enumerate(tx['inputs']):
                    if tx['is_coinbase']:
                        input_data.append((tx['txid'], vin, None, None, inp['script_sig']))
                    else:
                        input_data.append((
                            tx['txid'], vin, inp['prev_hash'], 
                            inp['prev_index'], inp['script_sig']
                        ))
                        # Mark previous output as spent
                        cursor.execute(
                            "UPDATE outputs SET spent = TRUE "
                            "WHERE txid = %s AND vout = %s",
                            (inp['prev_hash'], inp['prev_index'])
                        )
                
                execute_batch(
                    cursor,
                    "INSERT INTO inputs (txid, vin, prev_txid, prev_vout, script_sig) "
                    "VALUES (%s, %s, %s, %s, %s) ON CONFLICT (txid, vin) DO NOTHING",
                    input_data
                )
            
            block_hashes.append(block_hash)
            
            # Commit every 100 blocks
            if len(block_hashes) % 100 == 0:
                conn.commit()
                print(f"Processed {len(block_hashes)} blocks...")
    
    # Final commit
    conn.commit()
    cursor.close()
    conn.close()
    
    print(f"Successfully processed {len(block_hashes)} blocks from {dat_path}")
    return block_hashes

if __name__ == "__main__":
    # Example usage
    dat_file = "/home/btc-user/.bitcoin/blocks/blk00000.dat"  
    blocks = read_all_blocks_to_sql(dat_file)
    print(f"Inserted {len(blocks)} blocks into the database")