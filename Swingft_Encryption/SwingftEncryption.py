import os
import re
import sys
import base64
import random
from collections import defaultdict
import subprocess
try:
    from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
except ImportError:
    subprocess.check_call([sys.executable, "-m", "pip", "install", "cryptography"])
    from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

from typing import Optional

# === 설정 ===
KEY_BYTE_LEN = 32
NUM_CHUNKS = 4

# === 암호화 제외 대상 로드 ===
def load_excluded_set(path: str, source_root: str) -> dict[str, set[str]]:
    excluded = defaultdict(set)
    with open(path, encoding='utf-8') as f:
        for line in f:
            if '->' in line and line.startswith("STR:"):
                _, rest = line.split("STR:", 1)
                file, string = rest.strip().split('->', 1)
                file = file.strip()
                string = string.strip()
                if string.startswith('"') and string.endswith('"'):
                    string = string[1:-1]
                rel_file = os.path.relpath(file, source_root)
                excluded[rel_file].add(string)
    return excluded

def load_excluded_numbers(path: str, source_root: str) -> dict[str, dict[str, str]]:
    result = defaultdict(dict)
    with open(path, encoding='utf-8') as f:
        for line in f:
            if line.startswith("NUM:") and "->" in line:
                _, rest = line.split("NUM:", 1)
                file, declaration = rest.strip().split("->", 1)
                rel_file = os.path.relpath(file.strip(), source_root)
                name_and_type, value = declaration.strip().split("=", 1)
                result[rel_file][value.strip()] = name_and_type.strip()
    return result

# === 루트 탐색 ===
def find_encryption_root(start_dir: str) -> str:
    for root, dirs, _ in os.walk(start_dir):
        for d in dirs:
            if d.endswith(".xcodeproj") or d.endswith(".xcworkspace"):
                return root
    raise RuntimeError("Xcode 프로젝트를 찾을 수 없습니다.")

# === Swift 파일 수집 ===
def collect_swift_files(encryption_root: str) -> list[str]:
    swift_files = []
    for dirpath, _, filenames in os.walk(encryption_root):
        for file in filenames:
            if file.endswith(".swift") and not file.startswith(".") and file != "Package.swift":
                swift_files.append(os.path.join(dirpath, file))
    return swift_files

# === AppDelegate 경로 찾기 ===
def find_app_delegate_path(files: list[str]) -> Optional[str]:
    for path in files:
        if os.path.basename(path) == "AppDelegate.swift":
            return os.path.dirname(path)
    return None

# === 암호화 함수 ===
def encrypt_string(plaintext: str, cipher: ChaCha20Poly1305) -> str:
    nonce = os.urandom(12)
    ciphertext = cipher.encrypt(nonce, plaintext.encode("utf-8"), None)
    combined = nonce + ciphertext
    b64 = base64.b64encode(combined).decode("utf-8")
    return f'SwingftEncryption.resolve("{b64}")'

def encrypt_number_literal(num_literal: str, cipher: ChaCha20Poly1305, inferred_type: str) -> str:
    encrypted = encrypt_string(num_literal, cipher)
    if inferred_type == "Int":
        return f'Int({encrypted})!'
    elif inferred_type == "Double":
        return f'Double({encrypted})!'
    elif inferred_type == "Float":
        return f'Float({encrypted})!'
    else:
        return f'{inferred_type}({encrypted})!'

# === 메인 ===
if len(sys.argv) < 3:
    print("사용법: python encrypt_and_replace.py <source_root_dir> <excluded_txt_path>")
    sys.exit(1)

SOURCE_ROOT = sys.argv[1]
EXCLUDED_PATH = sys.argv[2]

ENCRYPTION_ROOT = find_encryption_root(SOURCE_ROOT)
swift_files = collect_swift_files(ENCRYPTION_ROOT)

excluded_map = load_excluded_set(EXCLUDED_PATH, ENCRYPTION_ROOT)
excluded_numbers = load_excluded_numbers(EXCLUDED_PATH, ENCRYPTION_ROOT)

KEY = ChaCha20Poly1305.generate_key()
CIPHER = ChaCha20Poly1305(KEY)

string_literal_pattern = re.compile(r'"(\\.|[^"\\])*"')
number_decl_pattern = re.compile(r'(\b(?:let|var)\s+\w+(?::\s*[\w<>]+)?\s*=\s*)(\d+(\.\d+)?)')

for file_path in swift_files:
    try:
        with open(file_path, encoding='utf-8') as f:
            content = f.read()

        rel_path = os.path.relpath(file_path, ENCRYPTION_ROOT)

        def replacer(match):
            raw = match.group(0)
            clean_str = raw.strip('"')
            if clean_str in excluded_map.get(rel_path, set()):
                return raw
            return encrypt_string(clean_str, CIPHER)

        def number_replacer(match):
            prefix = match.group(1)
            number = match.group(2)
            full_decl = excluded_numbers.get(rel_path, {}).get(number)
            if not full_decl:
                return match.group(0)
            inferred_type = full_decl.split(":")[1].strip() if ":" in full_decl else "Double"
            return f"{prefix}{encrypt_number_literal(number, CIPHER, inferred_type)}"

        new_content = re.sub(string_literal_pattern, replacer, content)
        new_content = re.sub(number_decl_pattern, number_replacer, new_content)

        if new_content != content:
            if "import StringSecurity" not in content:
                lines = new_content.splitlines()
                for i, line in enumerate(lines):
                    if line.strip().startswith("import "):
                        continue
                    else:
                        lines.insert(i, "import StringSecurity")
                        break
                new_content = "\n".join(lines)

            with open(file_path, "w", encoding="utf-8") as f:
                f.write(new_content)
            #print(f"암호화 완료: {file_path}")

    except Exception as e:
        print(f"실패: {file_path} – {e}")

# === 키 조각 삽입 ===

APP_DELEGATE_DIR = find_app_delegate_path(swift_files)

if not APP_DELEGATE_DIR:
    print("AppDelegate.swift 경로를 찾을 수 없음")
    sys.exit(1)

same_module_files = [path for path in swift_files if path.startswith(APP_DELEGATE_DIR)]
selected_chunk_count = min(max(len(same_module_files), 1), 4)  # 최소 1, 최대 4

CHUNK_SIZE = KEY_BYTE_LEN // selected_chunk_count
masks = [os.urandom(CHUNK_SIZE) for _ in range(selected_chunk_count)]
chunks = []
for i in range(selected_chunk_count):
    start = i * CHUNK_SIZE
    end = (i + 1) * CHUNK_SIZE if i < selected_chunk_count - 1 else KEY_BYTE_LEN
    chunks.append(KEY[start:end])

encoded_chunks = [bytes(c ^ m for c, m in zip(chunk, mask)) for chunk, mask in zip(chunks, masks)]

if len(same_module_files) < 2:
    print("Swift 파일이 2개 미만입니다. 하나의 파일에 모든 키 조각을 삽입합니다.")
    single_file = same_module_files[0] if same_module_files else swift_files[0]

    for i in range(selected_chunk_count):
        encoded = ", ".join(str(b) for b in encoded_chunks[i])
        mask = ", ".join(str(b) for b in masks[i])
        code = f"""
extension SwingftKey {{
    static let encoded{i+1}: [UInt8] = [{encoded}]
    static let mask{i+1}: [UInt8] = [{mask}]
}}
"""
        with open(single_file, "a", encoding="utf-8") as f:
            f.write(code)
        print(f"encoded{i+1} 및 mask{i+1} 삽입 완료 → {single_file}")

else:
    random.shuffle(same_module_files)
    used_files = set()

    for i in range(selected_chunk_count):
        available_files = [f for f in same_module_files if f not in used_files]

        if len(available_files) >= 2:
            encoded_file = available_files[0]
            mask_file = available_files[1]
            used_files.update([encoded_file, mask_file])
        elif len(available_files) == 1:
            encoded_file = mask_file = available_files[0]
            used_files.add(encoded_file)
        else:
            encoded_file = mask_file = random.choice(list(same_module_files))
            print(f"encoded{i+1} & mask{i+1} 같은 파일에 삽입 → {encoded_file}")

        encoded = ", ".join(str(b) for b in encoded_chunks[i])
        mask = ", ".join(str(b) for b in masks[i])

        encoded_code = f"""
extension SwingftKey {{
    static let encoded{i+1}: [UInt8] = [{encoded}]
}}
"""
        mask_code = f"""
extension SwingftKey {{
    static let mask{i+1}: [UInt8] = [{mask}]
}}
"""

        with open(encoded_file, "a", encoding="utf-8") as f:
            f.write(encoded_code)
        #print(f"encoded{i+1} 삽입 완료 → {encoded_file}")

        if mask_file != encoded_file:
            with open(mask_file, "a", encoding="utf-8") as f:
                f.write(mask_code)
            #print(f"mask{i+1} 삽입 완료 → {mask_file}")
        else:
            with open(mask_file, "a", encoding="utf-8") as f:
                f.write(mask_code)
            #print(f"mask{i+1} 삽입 완료 (같은 파일) → {mask_file}")

# AppDelegate 수정
try:
    subprocess.run([sys.executable, os.path.join(os.path.dirname(__file__), "modify_appdelegate.py"), SOURCE_ROOT], check=True)
except subprocess.CalledProcessError as e:
    print(f" AppDelegate 수정 실패: {e}")
