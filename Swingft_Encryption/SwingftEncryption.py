
import os
import re
import sys
import base64
import random
import shutil
from collections import defaultdict

try:
    from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
except ImportError:
    import subprocess
    subprocess.check_call([sys.executable, "-m", "pip", "install", "cryptography"])
    from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

KEY_BYTE_LEN = 32

def insert_import_and_key(path, chunk_count: int):
    with open(path, encoding='utf-8') as f:
        lines = f.readlines()
    if any('import StringSecurity' in l for l in lines):
        return
    insert_index = 0
    for i, line in enumerate(lines):
        if line.strip().startswith('import '):
            insert_index = i + 1
    encoded_vars = ", ".join(f"encoded{i+1}" for i in range(chunk_count))
    mask_vars = ", ".join(f"mask{i+1}" for i in range(chunk_count))
    key_code = f'''
import StringSecurity

enum SwingftKey {{
    static func combinedKey() -> Data {{
        var key = [UInt8]()
        let encodedParts: [[UInt8]] = [{encoded_vars}]
        let maskParts: [[UInt8]] = [{mask_vars}]
        for swingft1 in 0..<encodedParts.count {{
            for swingft2 in 0..<encodedParts[swingft1].count {{
                key.append(encodedParts[swingft1][swingft2] ^ maskParts[swingft1][swingft2])
            }}
        }}
        return Data(key)
    }}
}}
'''.splitlines(keepends=True)
    lines[insert_index:insert_index] = key_code
    with open(path, 'w', encoding='utf-8') as f:
        f.writelines(lines)


def detect_main_entry(files):
    for path in files:
        try:
            with open(path, encoding='utf-8') as f:
                content = f.read()
            if re.search(r'@main\s+struct\s+\w+\s*:\s*App', content):
                return path, 'swiftui'
            if re.search(r'class\s+\w+\s*:\s*UIResponder\s*,\s*UIApplicationDelegate', content):
                return path, 'uikit'
        except Exception:
            continue
    return None, None

def patch_uikit_delegate(path):
    with open(path, encoding='utf-8') as f:
        lines = f.readlines()
    inserted = False
    class_start = -1
    class_end = -1
    method_index = -1
    brace_count = 0
    for i, line in enumerate(lines):
        if re.search(r'class\s+\w+\s*:\s*UIResponder\s*,\s*UIApplicationDelegate', line):
            class_start = i
            break
    if class_start == -1:
        return
    for i in range(class_start, len(lines)):
        brace_count += lines[i].count('{')
        brace_count -= lines[i].count('}')
        if brace_count == 0:
            class_end = i
            break
    for i in range(class_start, class_end):
        if 'didFinishLaunchingWithOptions' in lines[i]:
            method_index = i
            break
    if method_index != -1:
        for j in range(method_index, class_end):
            if 'SwingftEncryption.configure' in lines[j]:
                return
        for j in range(method_index, class_end):
            if '{' in lines[j]:
                insert_line = j + 1
                lines.insert(insert_line, '        let key = SwingftKey.combinedKey()\n')
                lines.insert(insert_line + 1, '        SwingftEncryption.configure(key: key)\n')
                inserted = True
                break
    else:
        new_func = [
            '    func application(_ application: UIApplication, didFinishLaunchingWithOptions launchOptions: [UIApplication.LaunchOptionsKey: Any]?) -> Bool {\n',
            '        let key = SwingftKey.combinedKey()\n',
            '        SwingftEncryption.configure(key: key)\n',
            '        return true\n',
            '    }\n'
        ]
        lines[class_end:class_end] = ['\n'] + new_func
        inserted = True
    if inserted:
        with open(path, 'w', encoding='utf-8') as f:
            f.writelines(lines)

def patch_swiftui_struct(path):
    with open(path, encoding='utf-8') as f:
        lines = f.readlines()
    inserted = False
    for i, line in enumerate(lines):
        if 'init()' in line:
            for j in range(i, len(lines)):
                if '{' in lines[j]:
                    lines.insert(j + 1, '        let key = SwingftKey.combinedKey()\n')
                    lines.insert(j + 2, '        SwingftEncryption.configure(key: key)\n')
                    inserted = True
                    break
            break
    if not inserted:
        for i, line in enumerate(lines):
            if 'struct' in line and ': App' in line:
                for j in range(i, len(lines)):
                    if '{' in lines[j]:
                        insert_at = j + 1
                        init_func = [
                            '    init() {\n',
                            '        let key = SwingftKey.combinedKey()\n',
                            '        SwingftEncryption.configure(key: key)\n',
                            '    }\n'
                        ]
                        lines[insert_at:insert_at] = init_func
                        inserted = True
                        break
                break
    if inserted:
        with open(path, 'w', encoding='utf-8') as f:
            f.writelines(lines)

def patch_entry(files, chunk_count):
    entry_path, entry_type = detect_main_entry(files)
    if not entry_path:
        print("진입점 파일을 찾을 수 없습니다.")
        return None, None
    insert_import_and_key(entry_path, chunk_count)
    if entry_type == 'uikit':
        patch_uikit_delegate(entry_path)
    elif entry_type == 'swiftui':
        patch_swiftui_struct(entry_path)
    print(f"진입점 패치 완료: {entry_path} ({entry_type})")
    return entry_path, entry_type

def insert_global_import(swift_files):
    for path in swift_files:
        with open(path, encoding='utf-8') as f:
            lines = f.readlines()
        if any("import StringSecurity" in line for line in lines):
            continue
        insert_idx = 0
        for i, line in enumerate(lines):
            if line.strip().startswith("import "):
                insert_idx = i + 1
        lines.insert(insert_idx, "import StringSecurity\n")
        with open(path, "w", encoding="utf-8") as f:
            f.writelines(lines)

def copy_StringSecurity_folder(source_root):
    local_path = os.path.join(os.path.dirname(__file__), "StringSecurity")
    if not os.path.exists(local_path):
        print("StringSecurity 폴더가 존재하지 않습니다.")
        return
    for dirpath, dirnames, _ in os.walk(source_root):
        for d in dirnames:
            if d.endswith(('.xcodeproj', '.xcworkspace')):
                target = os.path.join(dirpath, "StringSecurity")
                if not os.path.exists(target):
                    shutil.copytree(local_path, target)
                    print(f"StringSecurity 폴더 복사됨: {target}")
                else:
                    print(f"StringSecurity 이미 존재함: {target}")
                return

def load_excluded_set(path: str):
    excluded = defaultdict(set)
    with open(path, encoding='utf-8') as f:
        for line in f:
            if '->' in line and line.startswith("STR:"):
                _, rest = line.split("STR:", 1)
                file, string = rest.strip().split('->', 1)
                abs_file = os.path.abspath(file.strip())
                excluded[abs_file].add(string.strip().strip('"'))
    return excluded

def load_excluded_numbers(path: str):
    result = defaultdict(dict)
    with open(path, encoding='utf-8') as f:
        for line in f:
            if line.startswith("NUM:") and "->" in line:
                _, rest = line.split("NUM:", 1)
                file, declaration = rest.strip().split("->", 1)
                abs_file = os.path.abspath(file.strip())
                name_and_type, value = declaration.strip().split("=", 1)
                result[abs_file][value.strip()] = name_and_type.strip()
    return result

def encrypt_and_insert(source_root: str, excluded_path: str):
    swift_files = []
    for dirpath, _, filenames in os.walk(source_root):
        for file in filenames:
            if file.endswith(".swift") and not file.startswith(".") and file != "Package.swift":
                swift_files.append(os.path.join(dirpath, file))
    if not swift_files:
        print("Swift 파일 없음")
        return
    count = 1 if len(swift_files) == 1 else 2 if len(swift_files) < 4 else 4
    entry_path, entry_type = patch_entry(swift_files, count)
    if not entry_path:
        return
    key = ChaCha20Poly1305.generate_key()
    chunk_size = KEY_BYTE_LEN // count
    masks = [os.urandom(chunk_size) for _ in range(count)]
    chunks = [key[i*chunk_size:(i+1)*chunk_size if i < count-1 else KEY_BYTE_LEN] for i in range(count)]
    encoded_chunks = [bytes(c ^ m for c, m in zip(chunk, mask)) for chunk, mask in zip(chunks, masks)]

    module_dir = os.path.dirname(entry_path)
    same_module_files = [f for f in swift_files if f.startswith(module_dir + os.sep)]
    if len(same_module_files) < count:
        print(f" 같은 모듈 내 Swift 파일 수 부족: {len(same_module_files)}개")
        return
    random.shuffle(same_module_files)
    for i in range(count):
        encoded = ", ".join(str(b) for b in encoded_chunks[i])
        mask = ", ".join(str(b) for b in masks[i])
        code_e = f"extension SwingftKey {{\n    static let encoded{i+1}: [UInt8] = [{encoded}]\n}}\n"
        code_m = f"extension SwingftKey {{\n    static let mask{i+1}: [UInt8] = [{mask}]\n}}\n"
        ef = mf = same_module_files[i]
        with open(ef, "a", encoding="utf-8") as f:
            f.write(code_e)
        with open(mf, "a", encoding="utf-8") as f:
            f.write(code_m)

    excluded_map = load_excluded_set(excluded_path)
    excluded_numbers = load_excluded_numbers(excluded_path)
    cipher = ChaCha20Poly1305(key)
    string_pattern = re.compile(r'"(\\.|[^"\\])*"')
    number_pattern = re.compile(r'(\b(?:let|var)\s+\w+(?::\s*[\w<>]+)?\s*=\s*)(\d+(\.\d+)?)')

    for file_path in swift_files:
        try:
            with open(file_path, encoding="utf-8") as f:
                content = f.read()
            abs_path = os.path.abspath(file_path)
            def replace_string(m):
                raw = m.group(0)
                clean = raw.strip('"')
                if clean in excluded_map.get(abs_path, set()):
                    return raw
                nonce = os.urandom(12)
                ct = cipher.encrypt(nonce, clean.encode(), None)
                b64 = base64.b64encode(nonce + ct).decode()
                return f'SwingftEncryption.resolve("{b64}")'
            def replace_number(m):
                prefix, number = m.group(1), m.group(2)
                full_decl = excluded_numbers.get(abs_path, {}).get(number)
                if not full_decl:
                    return m.group(0)
                inferred_type = full_decl.split(":")[1].strip() if ":" in full_decl else "Double"
                encrypted = replace_string(re.match(r'"[^"]+"', f'"{number}"'))
                return f"{prefix}{inferred_type}({encrypted})!"
            new_content = re.sub(string_pattern, replace_string, content)
            new_content = re.sub(number_pattern, replace_number, new_content)
            if new_content != content:
                with open(file_path, "w", encoding="utf-8") as f:
                    f.write(new_content)
        except Exception as e:
            print(f" 암호화 실패: {file_path} – {e}")

    insert_global_import(swift_files)
    copy_StringSecurity_folder(source_root)

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python SwingftEncryption.py <source_root> <excluded_json.path>")
        sys.exit(1)
    encrypt_and_insert(sys.argv[1], sys.argv[2])
