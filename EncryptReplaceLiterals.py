# pip install cryptography
try:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms
except ImportError:
    import subprocess
    import sys
    print("cryptography 라이브러리 설치")
    subprocess.check_call([sys.executable, "-m", "pip", "install", "cryptography"])
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms

import os
import sys
import random
import base64
import secrets
import argparse
import json
from pathlib import Path
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms

# === 키 생성 ===

def generate_chacha20_key_nonce():
    key = secrets.token_bytes(32)
    nonce = secrets.token_bytes(16)
    return key, nonce

def encode_base64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("utf-8")
# 조각
def split_into_chunks(encoded: str, parts: int = 4) -> list[str]:
    size = len(encoded) // parts
    chunks = [encoded[i:i+size] for i in range(0, len(encoded), size)]
    if len(chunks) > parts:
        chunks[-2] += chunks[-1]
        chunks = chunks[:-1]
    return chunks

# === 키 조각 변형 ===

def transform_chunks(chunks: list[str]) -> list[dict]:
    transformed = []
    for i, chunk in enumerate(chunks):
        if i == 0:
            transformed.append({"method": "reverse", "data": chunk[::-1]})
        elif i == 1:
            xorred = ''.join(chr(ord(c) ^ 0x3A) for c in chunk)
            transformed.append({"method": "xor", "data": xorred})
        elif i == 2:
            rotated = chunk[1:] + chunk[0]
            transformed.append({"method": "rotate", "data": rotated})
        else:
            transformed.append({"method": "plain", "data": chunk})
    return transformed

# === Swift 파일 조작 ====

def find_swift_files(root: Path) -> list[Path]:
    swift_files = []
    for path in root.rglob("*.swift"):
        if os.access(path, os.W_OK) and not any(part.startswith('.') for part in path.parts):
            swift_files.append(path)
    return swift_files

def insert_chunk_into_swift(swift_path: Path, var_name: str, data: str, method: str, index: int):
    with open(swift_path, 'r') as f:
        lines = f.readlines()

    insert_index = find_insertion_point(lines)
    payload = generate_swift_variable(var_name, data, method, index)
    lines.insert(insert_index, payload + "\n")

    with open(swift_path, 'w') as f:
        f.writelines(lines)

def find_insertion_point(lines: list[str]) -> int:
    for i, line in enumerate(lines):
        if line.strip().startswith("import"):
            continue
        if line.strip() == "" or line.strip().startswith("//"):
            continue
        return i
    return 0

def generate_swift_variable(name: str, data: str, method: str, index: int) -> str:
    byte_array = ', '.join(str(ord(c)) for c in data)
    return f"let {name}: [UInt8] = [{byte_array}] // swingft_k{index + 1}_{method}" # 이걸 기반으로 복호화 할때 키 조각 찾기

# === 암호화 ===

def encrypt_chacha20_stream(plaintext: str, key: bytes, nonce: bytes) -> str:
    algorithm = algorithms.ChaCha20(key, nonce)
    cipher = Cipher(algorithm, mode=None)
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(plaintext.encode("utf-8"))
    return encode_base64(ciphertext)

# === 문자열 리터럴만 암호화 ===

def encrypt_extracted_literals(literals_path: Path, key: bytes, nonce: bytes) -> list[dict]:
    with open(literals_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    result = []
    for item in data:
        if item["type"] != "String":
            continue  # 문자열만 처리
        encrypted = encrypt_chacha20_stream(item["literal"], key, nonce)
        result.append({
            "file": item["file"],
            "original": item["literal"],
            "encrypted": encrypted
        })
    return result

# === Swift 코드 수정===

def patch_swift_files_by_literal(encrypted_items: list[dict]):
    grouped = {}
    for item in encrypted_items:
        file_path = Path(item["file"])
        grouped.setdefault(file_path, []).append(item)

    for file_path, items in grouped.items():
        with open(file_path, "r", encoding="utf-8") as f:
            content = f.read()

        original_content = content

        for item in items:
            original = item["original"]
            encrypted = item["encrypted"]
            quoted = f'"{original}"'
            replacement = f'Swingft.decrypt("{encrypted}")'

            if quoted in content:
                content = content.replace(quoted, replacement)
            else:
                print(f" '{quoted}' not found in {file_path}")

        if content != original_content:
            with open(file_path, "w", encoding="utf-8") as f:
                f.write(content)

# === 메인 ===

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--project-root", required=True)
    parser.add_argument("--literals", default="extracted_literals.json")
    args = parser.parse_args()

    project_root = Path(args.project_root)
    literals_path = Path(args.literals)
    swift_files = find_swift_files(project_root)
    if len(swift_files) < 4:
        sys.exit("Swift 파일이 4개 이상 필요")

    key, nonce = generate_chacha20_key_nonce()
    encrypted_literals = encrypt_extracted_literals(literals_path, key, nonce)
    patch_swift_files_by_literal(encrypted_literals)

    encoded = encode_base64(key + nonce)
    chunks = split_into_chunks(encoded)
    transformed = transform_chunks(chunks)
    random.shuffle(swift_files)
    selected_files = swift_files[:4]

    for index, (file, chunk) in enumerate(zip(selected_files, transformed)):
        var_name = f"__kpart_{secrets.token_hex(2)}"
        insert_chunk_into_swift(file, var_name, chunk["data"], chunk["method"], index)

    print("문자열 리터럴 암호화 및 키 조각 Swift 삽입")

if __name__ == "__main__":
    main()
