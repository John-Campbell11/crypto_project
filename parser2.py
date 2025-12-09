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
                magic_start_pos = f.tell()
                
                # --- STEP 1: READ and DECRYPT (Magic + Size + Header) ---
                
                # We need at least 8 bytes (Magic + Size) to proceed.
                raw_intro = f.read(8) 
                if len(raw_intro) < 8:
                    break

                if is_obfuscated:
                    # If obfuscated, the first 8 bytes must be decrypted to get the real size.
                    decrypted_intro = deobsfucate(raw_intro, OBFUSCATION_KEY)
                    magic = decrypted_intro[:4]
                    size_bytes = decrypted_intro[4:]
                else:
                    # If plaintext, use the raw bytes.
                    magic = raw_intro[:4]
                    size_bytes = raw_intro[4:]

                # Check for the correct Bitcoin magic number (if known) for extra robustness
                # NOTE: We can't check the magic here unless we know the expected value.
                # Assuming the size calculation is the critical point.
                
                block_size = int.from_bytes(size_bytes, "little")

                # --- STEP 2: READ HEADER and VARINT (Handle the remaining data) ---

                # Read the remaining 76 bytes of the header + all transaction data.
                # Total block size (excluding magic/size) is block_size.
                remaining_block_data_size = block_size
                
                raw_block_payload = f.read(remaining_block_data_size)

                if len(raw_block_payload) < remaining_block_data_size:
                    # This means we hit EOF unexpectedly, indicating truncation/corruption
                    f.seek(magic_start_pos) # Rewind and break
                    print(f"Warning: Corrupted block detected at block #{len(blocks) + 1}. Skipping.")
                    break 

                # --- STEP 3: DEOBFUSCATE THE PAYLOAD ---
                
                if is_obfuscated:
                    # Decrypt the remaining payload
                    decrypted_payload = deobsfucate(raw_block_payload, OBFUSCATION_KEY)
                else:
                    # Use the raw payload
                    decrypted_payload = raw_block_payload


                # --- STEP 4: SEPARATE DECRYPTED DATA ---

                # Decrypted header is the first 80 bytes of the decrypted payload
                decrypted_header = decrypted_payload[:80]

                # The transaction data starts after the 80-byte header.
                tx_data_start_pos = 80
                
                # Parse the VarInt for transaction count from the memory buffer (not stream)
                # NOTE: Your utilities.py file only showed read_varint_from_stream, 
                # but to parse from memory, we need the in-memory version or a combined approach.
                # For simplicity, we are assuming the VarInt is *just* after the header (80 bytes).
                # We must use an in-memory VarInt parser here, as the stream read failed in the previous attempt.

                # Temporary placeholder for in-memory VarInt parsing (Required for this approach)
                def read_varint_from_buffer(data, offset):
                    prefix = data[offset]
                    if prefix < 0xfd: return prefix, 1
                    elif prefix == 0xfd: return int.from_bytes(data[offset + 1:offset + 3], "little"), 3
                    elif prefix == 0xfe: return int.from_bytes(data[offset + 1:offset + 5], "little"), 5
                    else: return int.from_bytes(data[offset + 1:offset + 9], "little"), 9

                tx_count, varint_size = read_varint_from_buffer(decrypted_payload, tx_data_start_pos)
                
                # Transaction data starts after the 80-byte header AND the VarInt bytes
                decrypted_transactions_data_chunk = decrypted_payload[tx_data_start_pos + varint_size:]

                # --- Create SimpleBlock object with decrypted data ---
                # NOTE: SimpleBlock constructor expects header and data chunk.
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
