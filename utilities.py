# --- Low-Level Byte Parsing Utility ---

def read_varint(data: bytes, offset: int):
    """
    Read a Bitcoin varint at data[offset] from a raw byte buffer (in-memory parsing).
    
    This function is used by the SimpleBlock and SimpleTransaction classes to parse
    the contents of transactions that are already loaded into memory.

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

def deobsfucate(data: bytes, key: bytes) -> bytes:
    """
    Deobfuscates the given data using the provided key.
    This is a simple XOR-based deobfuscation.
    """
    key_length = len(key)
    return bytes(b ^ key[i % key_length] for i, b in enumerate(data))