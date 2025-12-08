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