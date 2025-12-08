# This file contains the main I/O logic and execution block for parsing 
# an obfuscated or plaintext Bitcoin .dat file, based on user input.

# Import the class definition
from block_class import SimpleBlock
# Import necessary utility functions
from utilities import read_varint_from_stream, deobsfucate

# --- Configuration: The Obfuscation Key ---
# The key provided by the user: 5ac1d292e7350efe
OBFUSCATION_KEY = bytes.fromhex("5ac1d292e7350efe")


# --- Main I/O Logic ---

def read_all_blocks(dat_path: str, is_obfuscated: bool = False):
    """
    Reads ALL blocks from a Bitcoin .dat file.
    If 'is_obfuscated' is True, it decrypts the block payload using OBFUSCATION_KEY.
    Returns them as a list of SimpleBlock objects.
    """
    blocks = []

    try:
        with open(dat_path, "rb") as f:
            while True: 
                # --- Read magic number (4 bytes) ---
                magic_start_pos = f.tell()
                magic = f.read(4)
                if len(magic) < 4:
                    break  # Stop when we hit EOF or the file is truncated

                # --- Read block size (4 bytes, little-endian) ---
                size_bytes = f.read(4)
                if len(size_bytes) < 4:
                    f.seek(magic_start_pos) 
                    break
                block_size = int.from_bytes(size_bytes, "little")

                # --- Read raw header (80 bytes) ---
                raw_header = f.read(80)
                if len(raw_header) < 80:
                    f.seek(magic_start_pos)
                    break 

                # --- Read transaction count (varint) and calculate its size ---
                varint_start_pos = f.tell()
                tx_count = read_varint_from_stream(f) 
                
                # NOTE: The VarInt *must* be read before the transactions data 
                # because the stream pointer needs to be moved past the VarInt.
                bytes_read_for_varint = f.tell() - varint_start_pos
                
                if bytes_read_for_varint == 0:
                    f.seek(magic_start_pos)
                    break 

                # Calculate the exact size of the remaining transactions payload
                remaining_data_size = block_size - 80 - bytes_read_for_varint

                # --- Read remaining transactions data chunk ---
                raw_transactions_data_chunk = f.read(remaining_data_size)
                if len(raw_transactions_data_chunk) < remaining_data_size:
                    print(f"Warning: Corrupted block detected at block #{len(blocks) + 1}. Skipping.")
                    break

                # --- DEOBFUSCATION / ASSIGNMENT STEP (Conditional Logic) ---
                if is_obfuscated:
                    # 1. Combine the raw header and the raw transactions data chunk 
                    #    into a single payload for decryption.
                    obfuscated_payload = raw_header + raw_transactions_data_chunk

                    # 2. Decrypt the entire block payload using the key.
                    decrypted_payload = deobsfucate(obfuscated_payload, OBFUSCATION_KEY)

                    # 3. Split the decrypted payload back into its components.
                    decrypted_header = decrypted_payload[:80]
                    decrypted_transactions_data_chunk = decrypted_payload[80:]
                else:
                    # Use raw data directly if not obfuscated
                    decrypted_header = raw_header
                    decrypted_transactions_data_chunk = raw_transactions_data_chunk

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
        
    # --- New User Prompt for Obfuscation ---
    obfuscation_input = input("Is the file obfuscated (y/n)? ").strip().lower()
    is_obfuscated = obfuscation_input in ('y', 'yes')

    mode_description = "reading and decrypting" if is_obfuscated else "reading (plaintext)"
    print(f"Attempting {mode_description} all blocks from: {dat_file_path}")
    
    # We wrap the main reading logic in a try/except block for better error messaging
    try:
        # Pass the boolean flag to the reading function
        blocks = read_all_blocks(dat_file_path, is_obfuscated=is_obfuscated)
        print(f"\nSuccessfully loaded {len(blocks)} blocks from the file.\n")
        
        if blocks:
            print(blocks[0])  # Print the first block's details as a sample
            block0_transactions = blocks[0].transactions
            print(f"\nFirst block contains {len(block0_transactions)} transactions.\n")
            
            for tx in block0_transactions[:3]:  # Print first 3 transactions of block 0
                print(tx)
        
    except FileNotFoundError:
        print(f"Error: The file '{dat_file_path}' was not found. Please check the path.")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")