import hashlib
from typing import List
from datetime import datetime
# Import the byte parsing helper for in-memory parsing
from utilities import read_varint
# Import the dependency class
from transaction_class import SimpleTransaction

class SimpleBlock:
    """
    A class to calculate the hash of a Bitcoin-like block based only on its 
    header, parse the contained transactions, and calculate its timestamp.
    """

    def __init__(self, header: bytes, transactions_data: bytes):
        self.header = header
        self.timestamp = SimpleBlock.calculate_timestamp(header) # Calculate and store timestamp
        # decode_transactions will call split_transactions and create SimpleTransaction objects
        self.transactions = self.decode_transactions(transactions_data)
        self.hash = self.calculate_hash()

    def calculate_hash(self):
        """Calculates the block hash (double SHA-256 of the 80-byte header)."""
        hash1 = hashlib.sha256(self.header).digest()
        hash2 = hashlib.sha256(hash1).digest()
        reversed_hash = hash2[::-1]
        return reversed_hash.hex()
    
    @staticmethod
    def calculate_timestamp(header: bytes) -> datetime:
        """
        Extracts and converts the Unix epoch timestamp from the 80-byte block header.
        The timestamp is located at bytes 68-71 (4 bytes, little-endian).
        """
        # Index 68 (inclusive) to 72 (exclusive)
        timestamp_bytes = header[68:72]
        if len(timestamp_bytes) != 4:
            # Should not happen with a valid 80-byte header
            return datetime.min
        
        # Convert little-endian bytes to integer (Unix epoch time)
        unix_timestamp = int.from_bytes(timestamp_bytes, "little")
        
        # Convert Unix timestamp to datetime object
        return datetime.fromtimestamp(unix_timestamp)

    def decode_transactions(self, transactions_data: bytes):
        """
        Reads through the raw transaction byte stream, builds SimpleTransaction
        objects, and returns them as a list.
        """
        transactions_list = []

        # Use the static methods defined in this class
        for raw_tx in SimpleBlock.split_transactions(transactions_data):
            tx_type = SimpleBlock.get_tx_type(raw_tx)
            # Create the transaction object using the imported class
            tx_obj = SimpleTransaction(raw_tx, tx_type)
            transactions_list.append(tx_obj)

        return transactions_list

    @staticmethod
    def split_transactions(transactions_data: bytes):
        """
        REAL Bitcoin transaction splitter (correct boundaries, no I/O parsing).
        Uses the read_varint utility.
        """
        offset = 0
        data_len = len(transactions_data)

        while offset < data_len:
            tx_start = offset

            # --- Version (4 bytes) ---
            offset += 4

            # --- Check for SegWit Marker + Flag ---
            is_segwit = False
            if offset + 1 < data_len and transactions_data[offset] == 0x00 and transactions_data[offset + 1] != 0x00:
                is_segwit = True
                offset += 2  # skip marker + flag

            # --- Input Count ---
            vin_count, size = read_varint(transactions_data, offset)
            offset += size

            # --- Skip Inputs ---
            for _ in range(vin_count):
                offset += 32  # prev tx hash
                offset += 4   # prev tx index

                script_len, size = read_varint(transactions_data, offset)
                offset += size
                offset += script_len  # scriptSig

                offset += 4  # sequence

            # --- Output Count ---
            vout_count, size = read_varint(transactions_data, offset)
            offset += size

            # --- Skip Outputs ---
            for _ in range(vout_count):
                offset += 8  # value (satoshis)

                pk_len, size = read_varint(transactions_data, offset)
                offset += size
                offset += pk_len  # scriptPubKey

            # --- Skip Witness Data if SegWit ---
            if is_segwit:
                for _ in range(vin_count):
                    item_count, size = read_varint(transactions_data, offset)
                    offset += size

                    for _ in range(item_count):
                        item_len, size = read_varint(transactions_data, offset)
                        offset += size
                        offset += item_len

            # --- Locktime (4 bytes) ---
            offset += 4

            # --- Yield full raw transaction ---
            yield transactions_data[tx_start:offset]

    @staticmethod
    def get_tx_type(transaction_data: bytes) -> str:
        """
        Determines if the transaction is Legacy or SegWit by checking the 
        Marker (0x00) and Flag (non-zero) bytes at indices 4 and 5.
        """
        if (
            len(transaction_data) > 5
            and transaction_data[4] == 0x00
            and transaction_data[5] != 0x00
        ):
            return "SEGWIT"
        else:
            return "LEGACY"

    def __repr__(self):
        tx_count = len(self.transactions) if isinstance(self.transactions, list) else 'N/A'
        return (f"--- SIMPLE BLOCK ---\n"
                f"Block Hash: {self.hash}\n"
                f"Timestamp: {self.timestamp.strftime('%Y-%m-%d %H:%M:%S')}\n"
                f"Transaction Count: {tx_count}\n")