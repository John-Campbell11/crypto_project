# This file contains the main I/O logic and execution block.

# Import the class definition
from block_class import SimpleBlock
# The file-stream helper function is now defined locally to minimize imports

# --- Helper Function for VarInt Parsing from Stream (I/O) ---

def read_varint_from_stream(f):
    """
    Reads a variable-length integer (VarInt) from the file stream.
    This is used to determine the count of transactions from the file stream.
    Returns the integer value. Note: This function moves the file pointer.
    """
    first_byte = f.read(1)
    if not first_byte:
        return 0
        
    value = first_byte[0]
    
    if value < 0xfd:
        # 1-byte VarInt (Value is 0x00 to 0xFC)
        return value
    elif value == 0xfd:
        # 3-byte VarInt (Value is next 2 bytes)
        return int.from_bytes(f.read(2), "little")
    elif value == 0xfe:
        # 5-byte VarInt (Value is next 4 bytes)
        return int.from_bytes(f.read(4), "little")
    elif value == 0xff:
        # 9-byte VarInt (Value is next 8 bytes)
        return int.from_bytes(f.read(8), "little")
    return 0


def read_all_blocks(dat_path: str):
    """
    Reads ALL blocks from a Bitcoin .dat file and
    returns them as a list of SimpleBlock objects.
    The loop continues until EOF is reached.
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
                    f.seek(magic_start_pos) # Rewind if partial read
                    break
                block_size = int.from_bytes(size_bytes, "little")

                # --- Read header (80 bytes) ---
                header = f.read(80)
                if len(header) < 80:
                    f.seek(magic_start_pos)
                    break 

                # --- Read transaction count (varint) and calculate its size ---
                varint_start_pos = f.tell()
                # Use the I/O specific varint reader
                tx_count = read_varint_from_stream(f) 
                
                # We need to know how many bytes read_varint consumed (1, 3, 5, or 9)
                bytes_read_for_varint = f.tell() - varint_start_pos
                
                if bytes_read_for_varint == 0:
                    f.seek(magic_start_pos)
                    break 

                # The remaining data size is the block_size minus the 80-byte header 
                # and the actual number of bytes used by the VarInt.
                remaining_data_size = block_size - 80 - bytes_read_for_varint

                # --- Read remaining transactions data (as a single chunk) ---
                transactions_data_chunk = f.read(remaining_data_size)
                if len(transactions_data_chunk) < remaining_data_size:
                    print(f"Warning: Corrupted block detected at block #{len(blocks) + 1}. Skipping.")
                    break  # Corrupted block data

                # --- Create SimpleBlock object ---
                block = SimpleBlock(header, transactions_data_chunk) 
                blocks.append(block)

    except FileNotFoundError:
        print(f"Error: The file path '{dat_path}' was not found.")
    except Exception as e:
        # Added general exception handling for robustness during file reading
        print(f"An unexpected error occurred during block parsing: {e}")

    return blocks


if __name__ == "__main__":
    # NOTE: You MUST change this path to a valid blkNNNNN.dat file on your system
    dat_file_path = ""

    dat_file_path = input("Enter the path to a Bitcoin blkNNNNN.dat file (or press Enter to use default): ").strip()
    
    print(f"Attempting to read all blocks from: {dat_file_path}")
    blocks = read_all_blocks(dat_file_path)

    print(f"\nSuccessfully loaded {len(blocks)} blocks from the file.\n")
    
    """
    # Print summary of the first 10 blocks found
    for i, block in enumerate(blocks[:10], start=0):
        tx_count = len(block.transactions)
        
        # Calculate total value of outputs in the first transaction (Coinbase tx)
        coinbase_tx = block.transactions[0]
        total_output_value = sum(txout.value for txout in coinbase_tx.vouts)
        
        # Extract the first 8 characters (4 bytes) and the last 8 characters (4 bytes)
        full_hash = block.hash
        if len(full_hash) >= 8:
            display_hash = f"{full_hash[:5]}-{full_hash[-5:]}"
        else:
            display_hash = full_hash # Fallback if hash is somehow too short
        
        print(f"Block {i}: Hash = {display_hash}, Time={block.timestamp.strftime('%Y-%m-%d %H:%M:%S')}, Tx Count={tx_count}")
        print(f"  > Coinbase Tx ID: {coinbase_tx.txid[:10]}... ({len(coinbase_tx.vins)} In, {len(coinbase_tx.vouts)} Out)")
        print(f"  > Total Block Reward/Fees (Output Sum): {total_output_value / 10**8:.8f} BTC")
    
    if len(blocks) > 10:
        print(f"\n... and {len(blocks) - 10} more blocks.")
    """
        
    print(blocks[0])  # Print the first block's details as a sample
    block0_transactions = blocks[0].transactions
    print(f"\nFirst block contains {len(block0_transactions)} transactions.\n")
    for tx in block0_transactions[:3]:  # Print first 3 transactions of block 0
        print(tx)
