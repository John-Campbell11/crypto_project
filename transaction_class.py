import hashlib
from typing import List
from utilities import read_varint

# --- Helper Classes for Transaction Components ---

class TxIn:
    """Represents a transaction input (vin)."""
    def __init__(self, prev_tx_hash: bytes, prev_tx_index: int, script_sig: bytes, sequence: int):
        self.prev_tx_hash = prev_tx_hash # 32 bytes
        self.prev_tx_index = prev_tx_index # 4 bytes
        self.script_sig = script_sig       # Variable length script
        self.sequence = sequence           # 4 bytes

    def __repr__(self):
        # Display hashes in reversed hex format for consistency
        return f"TxIn(prev_tx={self.prev_tx_hash[::-1].hex()[:8]}..., index={self.prev_tx_index})"

class TxOut:
    """Represents a transaction output (vout)."""
    def __init__(self, value: int, script_pubkey: bytes):
        self.value = value             # Amount in satoshis (8 bytes)
        self.script_pubkey = script_pubkey # Variable length script

    def __repr__(self):
        return f"TxOut(value={self.value / 10**8:.4f} BTC, script_len={len(self.script_pubkey)})"


# --- SimpleTransaction Class ---

class SimpleTransaction:
    """
    A class representing a Bitcoin transaction, now including full parsing 
    of inputs (vins) and outputs (vouts) for detailed analysis.
    """

    def __init__(self, raw_tx_data: bytes, tx_type: str):
        self.raw_tx_data = raw_tx_data
        self.tx_type = tx_type
        
        # New properties for parsed data
        self.version: int = 0
        self.vins: List[TxIn] = []
        self.vouts: List[TxOut] = []
        self.locktime: int = 0
        
        # Parse the data to populate all properties
        self._parse_full_transaction(raw_tx_data, tx_type)
        
        # Compute TXID after parsing
        self.txid = SimpleTransaction.compute_txid(raw_tx_data, tx_type)

    def _parse_full_transaction(self, tx: bytes, tx_type: str):
        """Parses the raw transaction bytes into structured components (version, vins, vouts, locktime)."""
        
        offset = 0
        
        # 1. Version (4 bytes, little-endian)
        self.version = int.from_bytes(tx[offset:offset+4], "little")
        offset += 4

        # 2. SegWit Marker/Flag check (if present)
        is_segwit = False
        if tx_type == "SEGWIT":
            # Marker (0x00) and Flag (non-zero)
            is_segwit = True
            offset += 2  # skip marker (0x00) + flag (0x01-0xFF)

        # 3. Input Count
        vin_count, size = read_varint(tx, offset)
        offset += size
        
        # 4. Inputs (TxIn)
        for _ in range(vin_count):
            prev_tx_hash = tx[offset:offset+32]
            offset += 32
            
            prev_tx_index = int.from_bytes(tx[offset:offset+4], "little")
            offset += 4
            
            script_len, size = read_varint(tx, offset)
            offset += size
            
            script_sig = tx[offset:offset + script_len]
            offset += script_len
            
            sequence = int.from_bytes(tx[offset:offset+4], "little")
            offset += 4
            
            self.vins.append(TxIn(prev_tx_hash, prev_tx_index, script_sig, sequence))

        # 5. Output Count
        vout_count, size = read_varint(tx, offset)
        offset += size
        
        # 6. Outputs (TxOut)
        for _ in range(vout_count):
            value = int.from_bytes(tx[offset:offset+8], "little") # Value in satoshis (8 bytes)
            offset += 8
            
            pk_len, size = read_varint(tx, offset)
            offset += size
            
            script_pubkey = tx[offset:offset + pk_len]
            offset += pk_len
            
            self.vouts.append(TxOut(value, script_pubkey))

        # 7. Skip Witness Data if SegWit (required to find locktime)
        if is_segwit:
            for _ in range(vin_count):
                item_count, size = read_varint(tx, offset)
                offset += size
                for _ in range(item_count):
                    item_len, size = read_varint(tx, offset)
                    offset += size
                    offset += item_len

        # 8. Locktime (4 bytes)
        self.locktime = int.from_bytes(tx[offset:offset+4], "little")
        # offset += 4 (We stop here)

    @staticmethod
    def compute_txid(raw_tx_data: bytes, tx_type: str) -> str:
        """
        Compute TXID. For segwit transactions we must hash the transaction
        serialization with the witness removed.
        """
        if tx_type == "SEGWIT":
            stripped = SimpleTransaction._strip_witness(raw_tx_data)
            data_to_hash = stripped
        else:
            data_to_hash = raw_tx_data

        first_hash = hashlib.sha256(data_to_hash).digest()
        second_hash = hashlib.sha256(first_hash).digest()
        # TXIDs are displayed little-endian
        return second_hash[::-1].hex()

    @staticmethod
    def _strip_witness(tx: bytes) -> bytes:
        """
        Given a full transaction byte string, return the serialization used for 
        TXID calculation (i.e., without marker/flag and without witness data).
        """
        if len(tx) < 4: return tx
        version = tx[0:4]
        offset = 4
        is_segwit = False
        
        # Detect segwit marker+flag
        if len(tx) > offset + 1 and tx[offset] == 0x00 and tx[offset + 1] != 0x00:
            is_segwit = True
            offset += 2  # skip marker + flag
        else:
            return tx

        # Parse vin_count
        vin_count, size = read_varint(tx, offset)
        offset += size

        # Skip inputs
        for _ in range(vin_count):
            offset += 32 + 4  # prev tx hash + prev index
            script_len, s = read_varint(tx, offset)
            offset += s + script_len  # scriptSig length + scriptSig
            offset += 4  # sequence

        # Parse vout_count
        vout_count, size = read_varint(tx, offset)
        offset += size

        # Skip outputs
        for _ in range(vout_count):
            offset += 8  # value (satoshis)
            pk_len, s = read_varint(tx, offset)
            offset += s + pk_len  # scriptPubKey length + scriptPubKey

        end_of_outputs = offset

        # Skip witness data
        for _ in range(vin_count):
            item_count, s = read_varint(tx, offset)
            offset += s
            for _ in range(item_count):
                item_len, s = read_varint(tx, offset)
                offset += s + item_len

        # Now offset points at locktime (4 bytes)
        locktime = tx[offset:offset + 4]

        # Build non-witness serialization:
        # version (4) + [vin_count..outputs] (which started after marker/flag)
        non_witness_body = tx[6:end_of_outputs]
        return version + non_witness_body + locktime
    
    def __repr__(self):
        return (f"--- SIMPLE TRANSACTION ---\n"
                f"TXID: {self.txid}\n"
                f"Type: {self.tx_type}\n"
                f"Version: {self.version}\n"
                f"Inputs: {len(self.vins)}\n"
                f"Outputs: {len(self.vouts)}\n"
                f"Locktime: {self.locktime}\n")