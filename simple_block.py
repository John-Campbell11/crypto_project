import hashlib


class SimpleTransaction:
    """
    A simplified class representing a Bitcoin transaction.

    For TXID computation:
    - LEGACY: double-SHA256 of the whole raw transaction bytes (as stored).
    - SEGWIT: double-SHA256 of the transaction serialization WITHOUT the
      marker/flag and WITHOUT the witness data (i.e., the legacy serialization).
    """

    def __init__(self, raw_tx_data: bytes, tx_type: str):
        self.raw_tx_data = raw_tx_data
        self.tx_type = tx_type
        self.txid = self.compute_txid()

    def compute_txid(self) -> str:
        """
        Compute TXID. For segwit transactions we must hash the transaction
        serialization with the witness removed.
        """
        if self.tx_type == "SEGWIT":
            stripped = self._strip_witness(self.raw_tx_data)
            data_to_hash = stripped
        else:
            data_to_hash = self.raw_tx_data

        first_hash = hashlib.sha256(data_to_hash).digest()
        second_hash = hashlib.sha256(first_hash).digest()
        # TXIDs are displayed little-endian
        return second_hash[::-1].hex()

    def __repr__(self):
        return f"Transaction(txid={self.txid[:10]}..., Type={self.tx_type})"

    # ----- Helpers for parsing / stripping witness -----
    @staticmethod
    def _read_varint(data: bytes, offset: int):
        """
        Read a Bitcoin varint at data[offset].
        Returns (value, size_in_bytes).
        """
        prefix = data[offset]
        if prefix < 0xfd:
            return prefix, 1
        elif prefix == 0xfd:
            return int.from_bytes(data[offset + 1:offset + 3], "little"), 3
        elif prefix == 0xfe:
            return int.from_bytes(data[offset + 1:offset + 5], "little"), 5
        else:
            return int.from_bytes(data[offset + 1:offset + 9], "little"), 9

    def _strip_witness(self, tx: bytes) -> bytes:
        """
        Given a full transaction byte string (including marker/flag/witness if present),
        return the serialization used for TXID calculation (i.e., without marker/flag
        and without witness data).

        Steps:
        - Read version (4 bytes).
        - If marker+flag present (segwit), they occupy bytes 4 and 5.
        - Parse inputs and outputs to find the end of outputs.
        - For segwit: return version + tx[6:end_of_outputs] + locktime
          (where tx[6:end_of_outputs] contains vin_count..outputs).
        - For non-segwit callers (shouldn't be called), just return tx.
        """
        # Basic sanity
        if len(tx) < 4:
            return tx

        # read version
        version = tx[0:4]
        offset = 4

        # detect segwit marker+flag
        is_segwit = False
        if len(tx) > offset + 1 and tx[offset] == 0x00 and tx[offset + 1] != 0x00:
            is_segwit = True
            # marker+flag are at bytes 4 and 5
            offset += 2
        else:
            # Not segwit — nothing to strip
            return tx

        # Now offset points to vin_count varint (for segwit)
        # We'll parse inputs and outputs to determine end_of_outputs
        # Parse vin_count
        vin_count, size = self._read_varint(tx, offset)
        offset += size

        # Skip inputs
        for _ in range(vin_count):
            # prev tx hash (32) + prev index (4)
            offset += 32
            offset += 4

            # scriptSig length (varint) + scriptSig
            script_len, s = self._read_varint(tx, offset)
            offset += s
            offset += script_len

            # sequence (4)
            offset += 4

        # Now offset is at vout_count varint
        vout_count, size = self._read_varint(tx, offset)
        offset += size

        # Skip outputs
        for _ in range(vout_count):
            # value (8)
            offset += 8

            # scriptPubKey length + scriptPubKey
            pk_len, s = self._read_varint(tx, offset)
            offset += s
            offset += pk_len

        # At this point, 'offset' is the end of the outputs.
        end_of_outputs = offset

        # Next comes witness data for each input, then locktime.
        # We must parse the witness to find where locktime starts.
        # Parse witness for each input
        for _ in range(vin_count):
            item_count, s = self._read_varint(tx, offset)
            offset += s
            for _ in range(item_count):
                item_len, s = self._read_varint(tx, offset)
                offset += s
                offset += item_len

        # Now offset points at locktime (4 bytes)
        locktime = tx[offset:offset + 4]

        # Build non-witness serialization:
        # version (4) + [vin_count..outputs] (which started at byte 6 in original segwit)
        # For segwit the vin_count was at tx[6], because bytes 4-5 were marker+flag.
        non_witness_body = tx[6:end_of_outputs]  # vin_count..outputs
        return version + non_witness_body + locktime


class SimpleBlock:
    """
    A class to calculate the hash of a Bitcoin-like block based only on its 
    header. The hash is derived from the header data, ensuring data integrity.
    """

    def __init__(self, header: bytes, transactions_data: bytes):
        self.header = header
        self.transactions = self.decode_transactions(transactions_data)
        self.hash = self.calculate_hash()

    def calculate_hash(self):
        hash1 = hashlib.sha256(self.header).digest()
        hash2 = hashlib.sha256(hash1).digest()
        reversed_hash = hash2[::-1]
        return reversed_hash.hex()  # reverse because Bitcoin uses little-endian

    def decode_transactions(self, transactions_data: bytes):
        """
        Reads through the raw transaction byte stream, builds SimpleTransaction
        objects, and returns them as a list.
        """
        transactions_list = []

        for raw_tx in self.split_transactions(transactions_data):
            tx_type = self.get_tx_type(raw_tx)
            tx_obj = SimpleTransaction(raw_tx, tx_type)
            transactions_list.append(tx_obj)

        return transactions_list

    def read_varint(self, data: bytes, offset: int):
        prefix = data[offset]

        if prefix < 0xfd:
            return prefix, 1
        elif prefix == 0xfd:
            return int.from_bytes(data[offset + 1:offset + 3], "little"), 3
        elif prefix == 0xfe:
            return int.from_bytes(data[offset + 1:offset + 5], "little"), 5
        else:
            return int.from_bytes(data[offset + 1:offset + 9], "little"), 9

    def split_transactions(self, transactions_data: bytes):
        """
        REAL Bitcoin transaction splitter (correct boundaries, no IO parsing).
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
            vin_count, size = self.read_varint(transactions_data, offset)
            offset += size

            # --- Skip Inputs ---
            for _ in range(vin_count):
                offset += 32  # prev tx hash
                offset += 4   # prev tx index

                script_len, size = self.read_varint(transactions_data, offset)
                offset += size
                offset += script_len  # scriptSig

                offset += 4  # sequence

            # --- Output Count ---
            vout_count, size = self.read_varint(transactions_data, offset)
            offset += size

            # --- Skip Outputs ---
            for _ in range(vout_count):
                offset += 8  # value (satoshis)

                pk_len, size = self.read_varint(transactions_data, offset)
                offset += size
                offset += pk_len  # scriptPubKey

            # --- Skip Witness Data if SegWit ---
            if is_segwit:
                for _ in range(vin_count):
                    item_count, size = self.read_varint(transactions_data, offset)
                    offset += size

                    for _ in range(item_count):
                        item_len, size = self.read_varint(transactions_data, offset)
                        offset += size
                        offset += item_len

            # --- Locktime (4 bytes) ---
            offset += 4

            # --- Yield full raw transaction ---
            yield transactions_data[tx_start:offset]

    def get_tx_type(self, transaction_data: bytes) -> str:
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



