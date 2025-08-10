import os
import re
import sys
import base64
import random
import shutil
import json
from collections import defaultdict

try:
    from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
except ImportError:
    import subprocess
    subprocess.check_call([sys.executable, "-m", "pip", "install", "cryptography"])
    from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

KEY_BYTE_LEN = 32


def load_rules_from_json(path: str):
    ex_strings = defaultdict(set)
    ex_numbers = defaultdict(dict)
    ex_lines   = defaultdict(set)

    with open(path, encoding='utf-8') as f:
        items = json.load(f)

    for obj in items:
        file_raw = obj.get("file", "")
        file_raw = re.sub(r"^(?:STR|NUM)\s*:\s*", "", file_raw)
        abs_file = os.path.realpath(file_raw)

        kind = (obj.get("kind") or "").upper()
        line = obj.get("line")
        value = obj.get("value")

        if not abs_file or not kind or value is None:
            continue

        if isinstance(line, int) and line > 0:
            ex_lines[abs_file].add(line)

        if kind == "STR":
            ex_strings[abs_file].add(str(value))
        elif kind == "NUM":
            m = re.search(
                r'(?P<name>\w+)\s*:\s*(?P<type>[\w\.<>]+)\s*=\s*(?P<num>[-+]?\d+(?:\.\d+)?)',
                str(value)
            )
            if m:
                name = m.group('name')
                typ  = m.group('type')
                num  = m.group('num')
                ex_numbers[abs_file][num] = f"{name}: {typ}"
            else:
                m2 = re.search(r'([-+]?\d+(?:\.\d+)?)', str(value))
                if m2:
                    num = m2.group(1)
                    ex_numbers[abs_file][num] = "value: Double"

    return ex_strings, ex_numbers, ex_lines


def load_excluded_set(path: str):
    ex_strings, _, _ = load_rules_from_json(path)
    return ex_strings, set()


def load_excluded_numbers(path: str):
    _, ex_numbers, _ = load_rules_from_json(path)
    return ex_numbers


def load_excluded_lines(path: str):
    _, _, ex_lines = load_rules_from_json(path)
    return ex_lines


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


def remove_comments_and_track(code: str):
    return []


def is_within_comment(pos, comment_spans):
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

    class_start = -1
    for i, line in enumerate(lines):
        if re.search(r'\bclass\s+\w+\s*:\s*UIResponder\s*,\s*UIApplicationDelegate\b', line):
            class_start = i
            break
    if class_start == -1:
        return

    depth = 0
    class_end = -1
    for i in range(class_start, len(lines)):
        depth += lines[i].count('{')
        depth -= lines[i].count('}')
        if depth == 0 and i > class_start:
            class_end = i
            break
    if class_end == -1:
        class_end = len(lines) - 1

    def find_method_range(token: str):
        method_start = -1
        for i in range(class_start, class_end + 1):
            if token in lines[i]:
                method_start = i
                depth = 0
                body_seen = False
                for k in range(i, class_end + 1):
                    depth += lines[k].count('{')
                    depth -= lines[k].count('}')
                    if '{' in lines[k]:
                        body_seen = True
                    if body_seen and depth == 0:
                        return method_start, k
                break
        return -1, -1

    def has_config_call(start, end):
        if start == -1:
            return False
        return any('SwingftEncryption.configure' in lines[j] for j in range(start, end + 1))

    def insert_config_in_method(start, end):
        for j in range(start, end + 1):
            brace_index = lines[j].find('{')
            if brace_index != -1:
                indent = re.match(r'\s*', lines[j]).group(0) + '    '
                insert_at = j + 1
                insert_lines = [
                    f'{indent}let key = SwingftKey.combinedKey()\n',
                    f'{indent}SwingftEncryption.configure(key: key)\n'
                ]
                lines[insert_at:insert_at] = insert_lines
                return True
        return False

    will_start, will_end = find_method_range('willFinishLaunchingWithOptions')
    if will_start != -1:
        if not has_config_call(will_start, will_end):
            if insert_config_in_method(will_start, will_end):
                with open(path, 'w', encoding='utf-8') as f:
                    f.writelines(lines)
        return


    did_start, did_end = find_method_range('didFinishLaunchingWithOptions')
    if did_start != -1:
        if not has_config_call(did_start, did_end):
            if insert_config_in_method(did_start, did_end):
                with open(path, 'w', encoding='utf-8') as f:
                    f.writelines(lines)
        return

    class_indent = re.match(r'\s*', lines[class_start]).group(0)
    method_indent = class_indent + '    '
    new_func = [
        '\n',
        f'{method_indent}func application(_ application: UIApplication,\n',
        f'{method_indent}                     willFinishLaunchingWithOptions launchOptions: [UIApplication.LaunchOptionsKey: Any]? = nil) -> Bool {{\n',
        f'{method_indent}    let key = SwingftKey.combinedKey()\n',
        f'{method_indent}    SwingftEncryption.configure(key: key)\n',
        f'{method_indent}    return true\n',
        f'{method_indent}}}\n'
    ]
    lines[class_end:class_end] = new_func
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
        return None, None
    insert_import_and_key(entry_path, chunk_count)
    if entry_type == 'uikit':
        patch_uikit_delegate(entry_path)
    elif entry_type == 'swiftui':
        patch_swiftui_struct(entry_path)
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
        except:
            pass


def copy_StringSecurity_folder(source_root):
    local_path = os.path.join(os.path.dirname(__file__), "StringSecurity")
    if not os.path.exists(local_path):
        return
    for dirpath, dirnames, _ in os.walk(source_root):
        for d in dirnames:
            if d.endswith(('.xcodeproj', '.xcworkspace')):
                target = os.path.join(dirpath, "StringSecurity")
                if not os.path.exists(target):
                    shutil.copytree(local_path, target)
                return


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
        return

    swift_files = []
    for dirpath, dirnames, filenames in os.walk(target_root):
        dirnames[:] = [d for d in dirnames if not d.startswith("Framework")]
        for file in filenames:
            if file.endswith(".swift") and not file.startswith(".") and file != "Package.swift":
                swift_files.append(os.path.join(dirpath, file))
    if not swift_files:
        return

    count = 1 if len(swift_files) == 1 else 2 if len(swift_files) < 4 else 4
    key = ChaCha20Poly1305.generate_key()
    chunk_size = KEY_BYTE_LEN // count
    masks = [os.urandom(chunk_size) for _ in range(count)]
    chunks = [key[i*chunk_size:(i+1)*chunk_size if i < count-1 else KEY_BYTE_LEN] for i in range(count)]
    encoded_chunks = [bytes(c ^ m for c, m in zip(chunk, mask)) for chunk, mask in zip(chunks, masks)]
    cipher = ChaCha20Poly1305(key)

    excluded_map, _ = load_excluded_set(excluded_path)
    excluded_numbers = load_excluded_numbers(excluded_path)
    excluded_lines = load_excluded_lines(excluded_path)

    string_pattern = re.compile(r'("""(?:\\.|"(?!""")|[^"])*?"""|"(?:\\.|[^"\\])*")', re.DOTALL)
    number_pattern = re.compile(r'(\b(?:let|var)\s+\w+(?::\s*[\w<>]+)?\s*=\s*)(\d+(\.\d+)?)')

    for file_path in swift_files:
        try:
            with open(file_path, encoding="utf-8") as f:
                content = f.read()
            abs_path = os.path.realpath(file_path)
            ex_lines_set = excluded_lines.get(abs_path, set())
            ex_contents = excluded_map.get(abs_path, set())
            ex_nums = excluded_numbers.get(abs_path, {})

            def match_overlaps_excluded(m):
                start_ln = line_no_of(content, m.start())
                end_ln   = line_no_of(content, m.end()-1)
                return any(ln in ex_lines_set for ln in range(start_ln, end_ln+1))

            def replace_string(m):
                if m.group(0) in ex_contents:
                    return m.group(0)
                if match_overlaps_excluded(m):
                    return m.group(0)
                raw = m.group(0)
                inner = raw[3:-3] if raw.startswith('"""') else raw[1:-1]
                nonce = os.urandom(12)
                ct = cipher.encrypt(nonce, inner.encode(), None)
                b64 = base64.b64encode(nonce + ct).decode()
                return f'SwingftEncryption.resolve("{b64}")'

            def replace_number(m):
                if match_overlaps_excluded(m):
                    return m.group(0)
                prefix, number = m.group(1), m.group(2)
                full_decl = ex_nums.get(number)
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
        except:
            pass

    entry_path, _ = patch_entry(swift_files, count)
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
        ef = (preferred_files or fallback_files or [entry_path])[0]
        if ef in used_files:
            ef = (fallback_files or [entry_path])[0]
        used_files.add(ef)
        mf = (preferred_files or fallback_files or [ef])[0]
        if mf in used_files:
            mf = (fallback_files or [ef])[0]
        used_files.add(mf)
        encoded = ", ".join(str(b) for b in encoded_chunks[i])
        mask = ", ".join(str(b) for b in masks[i])
        with open(ef, "a", encoding="utf-8") as f:
            f.write(f"\nextension SwingftKey {{\n    static let encoded{i+1}: [UInt8] = [{encoded}]\n}}\n")
        with open(mf, "a", encoding="utf-8") as f:
            f.write(f"\nextension SwingftKey {{\n    static let mask{i+1}: [UInt8] = [{mask}]\n}}\n")

    insert_global_import(swift_files)
    copy_StringSecurity_folder(source_root)


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python SwingftEncryption.py <source_root> <excluded_String.json>")
        sys.exit(1)
    encrypt_and_insert(sys.argv[1], sys.argv[2])

