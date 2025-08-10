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


def remove_comments_and_track(code):
    
    line_comment = re.compile(r'//.*')
    block_comment = re.compile(r'/\*[\s\S]*?\*/')
    comment_spans = []
    for m in line_comment.finditer(code):
        comment_spans.append((m.start(), m.end()))
    for m in block_comment.finditer(code):
        comment_spans.append((m.start(), m.end()))
    comment_spans.sort()
    return comment_spans

def is_within_comment(pos, comment_spans):
    for s, e in comment_spans:
        if s <= pos < e:
            return True
    return False

def detect_main_entry(files):
    for path in files:
        try:
            with open(path, encoding='utf-8') as f:
                content = f.read()
            if re.search(r'@main\s+(struct|class)\s+\w+\s*:\s*App', content):
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

def insert_global_import(encrypted_files):
    for path in encrypted_files:
        try:
            with open(path, encoding='utf-8') as f:
                lines = f.readlines()
            if any("import StringSecurity" in line for line in lines):
                continue
            insert_idx = None
            for i, line in enumerate(lines):
                if line.strip().startswith("import "):
                    insert_idx = i
                    break
            if insert_idx is None:
                insert_idx = 0
            lines.insert(insert_idx, "import StringSecurity\n")
            with open(path, "w", encoding="utf-8") as f:
                f.writelines(lines)
        except Exception as e:
            print(f"import 삽입 실패: {path} – {e}")


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
        text = f.read()

    text = text.replace("STR ->", "STR:").replace("TR ->", "TR:")

    pattern = re.compile(
        r'^(?:STR|TR):\s*(?P<file>.*?)\s*->\s*(?P<lit>"""[\s\S]*?"""|"(?:\\.|[^"\\])*")\s*$',
        re.MULTILINE
    )

    for m in pattern.finditer(text):
        abs_file = os.path.abspath(m.group("file").strip())
        literal = m.group("lit")
        excluded[abs_file].add(literal)
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

def load_excluded_lines(path: str):
    mapping = defaultdict(set)
    rx = re.compile(r'^(?:STR|TR|NUM)?\:?\s*(.+?\.swift):(\d+)\s*->', re.IGNORECASE)
    with open(path, encoding='utf-8') as f:
        for raw in f:
            m = rx.match(raw.strip())
            if not m:
                continue
            file_path = os.path.abspath(m.group(1))
            ln = int(m.group(2))
            mapping[file_path].add(ln)
    return mapping

def line_no_of(text: str, pos: int) -> int:
    return text.count('\n', 0, pos) + 1


def encrypt_and_insert(source_root: str, excluded_path: str):
    target_root = None
    for dirpath, dirnames, filenames in os.walk(source_root):
        for d in dirnames:
            if d.endswith('.xcodeproj') or d.endswith('.xcworkspace'):
                target_root = dirpath
                break
        if target_root:
            break

    if not target_root:
        print(".xcodeproj 또는 .xcworkspace 디렉토리를 찾을 수 없습니다.")
        return

    swift_files = []
    for dirpath, _, filenames in os.walk(target_root):
        for file in filenames:
            if file.endswith(".swift") and not file.startswith(".") and file != "Package.swift":
                swift_files.append(os.path.join(dirpath, file))
    if not swift_files:
        print("Swift 파일 없음")
        return
    count = 1 if len(swift_files) == 1 else 2 if len(swift_files) < 4 else 4
    key = ChaCha20Poly1305.generate_key()
    chunk_size = KEY_BYTE_LEN // count
    masks = [os.urandom(chunk_size) for _ in range(count)]
    chunks = [key[i*chunk_size:(i+1)*chunk_size if i < count-1 else KEY_BYTE_LEN] for i in range(count)]
    encoded_chunks = [bytes(c ^ m for c, m in zip(chunk, mask)) for chunk, mask in zip(chunks, masks)]
    cipher = ChaCha20Poly1305(key)

    excluded_map = load_excluded_set(excluded_path)
    excluded_numbers = load_excluded_numbers(excluded_path)
    excluded_lines = load_excluded_lines(excluded_path)

    string_pattern = re.compile(r'("""(?:\\.|"(?!""")|[^"])*?"""|"(?:\\.|[^"\\])*")', re.DOTALL)
    number_pattern = re.compile(r'(\b(?:let|var)\s+\w+(?::\s*[\w<>]+)?\s*=\s*)(\d+(\.\d+)?)')

    for file_path in swift_files:
        try:
            with open(file_path, encoding="utf-8") as f:
                content = f.read()
            abs_path = os.path.abspath(file_path)
            comment_spans = remove_comments_and_track(content)

            ex_lines = excluded_lines.get(abs_path, set())
            ex_contents = excluded_map.get(abs_path, set())
            ex_nums = excluded_numbers.get(abs_path, {})

            def replace_string(m):
                ln = line_no_of(content, m.start())
                if ln in ex_lines:
                    return m.group(0)
                if is_within_comment(m.start(), comment_spans):
                    return m.group(0)

                raw = m.group(0)

                if raw in ex_contents:
                    return raw
                if raw.startswith('"""'):
                    inner = raw[3:-3]
                else:
                    inner = raw[1:-1]
                if inner in ex_contents:
                    return raw

                nonce = os.urandom(12)
                ct = cipher.encrypt(nonce, inner.encode(), None)
                b64 = base64.b64encode(nonce + ct).decode()
                return f'SwingftEncryption.resolve("{b64}")'

            def replace_number(m):
                ln = line_no_of(content, m.start())
                if ln in ex_lines:
                    return m.group(0)
                if is_within_comment(m.start(), comment_spans):
                    return m.group(0)

                prefix, number = m.group(1), m.group(2)
                full_decl = ex_nums.get(number)
                if not full_decl:
                    return m.group(0)
                inferred_type = full_decl.split(":")[1].strip() if ":" in full_decl else "Double"

                tmp_match = re.match(r'"[^"]+"', f'"{number}"')
                encrypted = replace_string(tmp_match)  
                return f"{prefix}{inferred_type}({encrypted})!"

            new_content = re.sub(string_pattern, replace_string, content)
            new_content = re.sub(number_pattern, replace_number, new_content)

            if new_content != content:
                with open(file_path, "w", encoding="utf-8") as f:
                    f.write(new_content)
        except Exception as e:
            print(f" 암호화 실패: {file_path} – {e}")

    entry_path, entry_type = patch_entry(swift_files, count)
    if not entry_path:
        return

    module_dir = os.path.dirname(entry_path)
    same_module_files = [f for f in swift_files if f.startswith(module_dir + os.sep)]

    preferred_files = [f for f in same_module_files if f != entry_path]
    fallback_files = same_module_files[:] if same_module_files else swift_files[:]
    random.shuffle(preferred_files)
    random.shuffle(fallback_files)

    used_files = set()
    for i in range(count):
        enc_file_candidates = [f for f in preferred_files if f not in used_files] or [f for f in fallback_files if f not in used_files] or [entry_path]
        ef = enc_file_candidates[0]
        used_files.add(ef)

        mask_file_candidates = [f for f in preferred_files if f not in used_files] or [f for f in fallback_files if f not in used_files] or [ef]
        mf = mask_file_candidates[0]
        used_files.add(mf)

        encoded = ", ".join(str(b) for b in encoded_chunks[i])
        mask = ", ".join(str(b) for b in masks[i])

        code_e = f"\nextension SwingftKey {{\n    static let encoded{i+1}: [UInt8] = [{encoded}]\n}}\n"
        code_m = f"\nextension SwingftKey {{\n    static let mask{i+1}: [UInt8] = [{mask}]\n}}\n"

        with open(ef, "a", encoding="utf-8") as f:
            f.write(code_e)
        with open(mf, "a", encoding="utf-8") as f:
            f.write(code_m)

    insert_global_import(swift_files)
    copy_StringSecurity_folder(source_root)


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python SwingftEncryption.py <source_root> <excluded_String.txt>")
        sys.exit(1)
    encrypt_and_insert(sys.argv[1], sys.argv[2])

