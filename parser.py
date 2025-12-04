from simple_block import SimpleBlock  # Import your existing class

def read_first_n_blocks(dat_path: str, n: int = 10):
    """
    Reads the first `n` blocks from a Bitcoin .dat file and
    returns them as a list of SimpleBlock objects.
    """
    blocks = []

    with open(dat_path, "rb") as f:
        while len(blocks) < n:
            # --- Read magic number ---
            magic = f.read(4)
            if not magic:
                break  # EOF
            # Bitcoin magic number check (optional)
            # mainnet = 0xD9B4BEF9, testnet = 0xDAB5BFFA
            # print("Magic:", magic.hex())

            # --- Read block size ---
            size_bytes = f.read(4)
            if len(size_bytes) < 4:
                break  # EOF / incomplete block
            block_size = int.from_bytes(size_bytes, "little")

            # --- Read header (80 bytes) ---
            header = f.read(80)
            if len(header) < 80:
                break  # EOF / corrupted block

            # --- Read transaction count (varint) ---
            tx_count_byte = f.read(1)
            if len(tx_count_byte) < 1:
                break  # EOF
            tx_count = tx_count_byte[0]

            # --- Read remaining transactions ---
            transactions_data = f.read(block_size - 80 - 1)
            if len(transactions_data) < (block_size - 80 - 1):
                break  # EOF / corrupted block

            # --- Create SimpleBlock object ---
            block = SimpleBlock(header, transactions_data)
            blocks.append(block)


    return blocks


if __name__ == "__main__":
    dat_file_path = "/Users/soupman/PycharmProjects/ScrapingBlockTransactions/blk00000.dat"
    first_10_blocks = read_first_n_blocks(dat_file_path, n=10)

    print(f"\nLoaded {len(first_10_blocks)} blocks.\n")
    for i, block in enumerate(first_10_blocks, start=1):
        print(f"Block {i}: Hash={block.hash}, Transactions={len(block.transactions)}")
