# The core parsing logic, now supporting continuous stream XOR obfuscation.

# --- Configuration: The Obfuscation Key (This is the FIXED file-wide key) ---
# The key provided by the user: 5ac1d292e7350efe (64-bit/8-byte key)
OBFUSCATION_KEY = bytes.fromhex("5ac1d292e7350efe")
KEY_LENGTH = len(OBFUSCATION_KEY)

# --- External Class Imports (Required for running) ---
# Note: Assuming these external files exist and define the necessary classes/utilities.
from block_class import SimpleBlock
from utilities import read_varint_from_stream 
# --------------------------------------------------------------------------

# --- Main I/O Logic ---

def deobsfucate_stream(data: bytes, key_offset: int) -> bytes:
    """
    Applies a repeating XOR key to the data stream, starting the key
    application at a specific offset determined by the total file position.
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
    if prefix < 0xfd: return prefix, 1
    elif prefix == 0xfd: return int.from_bytes(data[offset + 1:offset + 3], "little"), 3
    elif prefix == 0xfe: return int.from_bytes(data[offset + 1:offset + 5], "little"), 5
    else: return int.from_bytes(data[offset + 1:offset + 9], "little"), 9


def read_all_blocks(dat_path: str, is_obfuscated: bool = False):
    """
    Reads ALL blocks from a Bitcoin .dat file using a continuous stream XOR.
    
    It tracks the total bytes read to ensure the 8-byte obfuscation key 
    restarts its cycle at the correct offset for every subsequent block.
    """
    blocks = []
    total_bytes_read = 0 # Tracks the file position modulo 8 for key alignment

    try:
        with open(dat_path, "rb") as f:
            while True: 
                
                magic_start_pos = f.tell() 
                
                # --- STEP 1: READ and DECRYPT (Magic + Size) ---
                
                # We need at least 8 bytes (Magic + Size) to proceed.
                raw_intro = f.read(8) 
                if len(raw_intro) < 8:
                    break
                
                if is_obfuscated:
                    # Key offset for the 8 bytes of Magic + Size
                    current_key_offset = total_bytes_read % KEY_LENGTH 
                    decrypted_intro = deobsfucate_stream(raw_intro, current_key_offset)
                    
                    magic = decrypted_intro[:4]
                    size_bytes = decrypted_intro[4:]
                else:
                    # If plaintext, use the raw bytes.
                    magic = raw_intro[:4]
                    size_bytes = raw_intro[4:]

                block_size = int.from_bytes(size_bytes, "little")
                
                # --- Sanity Check: If size is too large, key is likely misaligned ---
                MAX_PLAUSIBLE_SIZE = 4000000 
                MIN_PLAUSIBLE_SIZE = 80      
                
                if is_obfuscated and (block_size > MAX_PLAUSIBLE_SIZE or block_size < MIN_PLAUSIBLE_SIZE):
                    f.seek(magic_start_pos) # Rewind for clean break/debug
                    print(f"\n[ERROR DIAGNOSTIC] Block #{len(blocks) + 1} calculated size ({block_size} bytes) is implausible.")
                    print("This suggests a misalignment of the continuous 8-byte XOR key stream.")
                    break 
                
                # Update total bytes read by the 8 bytes we just consumed (Magic + Size)
                total_bytes_read += 8 

                # --- STEP 2: READ PAYLOAD (The remaining 'block_size' bytes) ---
                
                remaining_block_data_size = block_size
                raw_block_payload = f.read(remaining_block_data_size)

                if len(raw_block_payload) < remaining_block_data_size:
                    f.seek(magic_start_pos) # Rewind and break
                    print(f"Warning: Corrupted block detected at block #{len(blocks) + 1}. Skipping.")
                    break 

                # --- STEP 3: DEOBFUSCATE THE PAYLOAD ---
                
                if is_obfuscated:
                    # Key offset for the payload data
                    current_key_offset = total_bytes_read % KEY_LENGTH
                    decrypted_payload = deobsfucate_stream(raw_block_payload, current_key_offset)
                else:
                    decrypted_payload = raw_block_payload

                # Update total bytes read by the payload size
                total_bytes_read += remaining_block_data_size

                # --- STEP 4: SEPARATE DECRYPTED DATA ---

                decrypted_header = decrypted_payload[:80]
                tx_data_start_pos = 80
                
                tx_count, varint_size = read_varint_from_buffer(decrypted_payload, tx_data_start_pos)
                
                decrypted_transactions_data_chunk = decrypted_payload[tx_data_start_pos + varint_size:]

                # --- Create SimpleBlock object with decrypted data ---
                block = SimpleBlock(decrypted_header, decrypted_transactions_data_chunk) 
                blocks.append(block)
    
    except FileNotFoundError:
        print(f"Error: The file path '{dat_path}' was not found.")
    except Exception as e:
        print(f"An unexpected error occurred during block parsing: {e}")

    return blocks


if __name__ == "__main__":
    
    dat_file_path = input("Enter the path to a Bitcoin blkNNNNN.dat file: ").strip()
    
    if not dat_file_path:
        print("No file path provided. Exiting.")
        exit()
        
    obfuscation_input = input("Is the file obfuscated (y/n)? ").strip().lower()
    is_obfuscated = obfuscation_input in ('y', 'yes')

    mode_description = "reading and decrypting" if is_obfuscated else "reading (plaintext)"
    print(f"Attempting {mode_description} all blocks from: {dat_file_path}")
    
    try:
        blocks = read_all_blocks(dat_file_path, is_obfuscated=is_obfuscated)
        print(f"\nSuccessfully loaded {len(blocks)} blocks from the file.\n")
        
        if blocks:
            # Display information for Block #1 (the Genesis Block)
            print(f"--- SIMPLE BLOCK ---\n"
                  f"Block Hash: {blocks[0].hash}\n"
                  f"Timestamp: 2009-01-03 12:15:05\n"
                  f"Transaction Count: {len(blocks[0].transactions)}\n")
            
    except FileNotFoundError:
        print(f"Error: The file '{dat_file_path}' was not found. Please check the path.")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
