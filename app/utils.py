def load_file(path: str) -> bytes:
    with open(path, "rb") as buffer:
        data = buffer.read()

    return data
