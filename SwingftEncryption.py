
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


SWIFT_SIMPLE_ESCAPES = {
    r'\n': '\n',
    r'\r': '\r',
    r'\t': '\t',
    r'\"': '"',
    r"\'": "'",
    r'\\': '\\',
    r'\0': '\0',
}

def swift_unescape(s: str) -> str:
    import re
    def _u(m):
        return chr(int(m.group(1), 16))
    s = re.sub(r'\\u\{([0-9A-Fa-f]+)\}', _u, s)
    for k, v in SWIFT_SIMPLE_ESCAPES.items():
        s = s.replace(k, v)
    return s


def load_included_from_json(path: str):
    in_strings = defaultdict(set)
    in_lines   = defaultdict(set)

    with open(path, encoding='utf-8') as f:
        items = json.load(f)

    for obj in items:
        if (obj.get("kind") or "").upper() != "STR":
            continue

        file_raw = obj.get("file", "")
        
        file_raw = re.sub(r"^(?:STR|NUM)\s*:\s*", "", file_raw)
        abs_file = os.path.realpath(file_raw)

        line = obj.get("line")
        value = obj.get("value")

        if not abs_file or value is None:
            continue

        
        if isinstance(line, int) and line > 0:
            in_lines[abs_file].add(line)

        in_strings[abs_file].add(str(value))

    return in_strings, in_lines



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


def insert_global_import(swift_files):
    for path in swift_files:
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


def encrypt_and_insert(source_root: str, included_json_path: str):
   
    in_strings, _ = load_included_from_json(included_json_path)
    STRING_RE = re.compile(r'("""(?:\\.|"(?!""")|[^"])*?"""|"(?:\\.|[^"\\])*")', re.DOTALL)


    target_root = None
    for dirpath, dirnames, _ in os.walk(source_root):
        if any(d.endswith(('.xcodeproj', '.xcworkspace')) for d in dirnames):
            target_root = dirpath
            break
    if not target_root:
        return

    swift_files = []
    for dirpath, dirnames, filenames in os.walk(target_root):
        dirnames[:] = [d for d in dirnames if not d.startswith("Framework")]
        for fn in filenames:
            if fn.endswith(".swift") and fn != "Package.swift" and not fn.startswith("."):
                swift_files.append(os.path.join(dirpath, fn))
    if not swift_files:
        return

   
    key = ChaCha20Poly1305.generate_key()
    cipher = ChaCha20Poly1305(key)

    for file_path in swift_files:
        if "StringSecurity" in file_path:
            continue  

        try:
            with open(file_path, encoding="utf-8") as f:
                content = f.read()

            abs_path = os.path.realpath(file_path)
            in_contents = in_strings.get(abs_path, set())

            def replace_string(m):
                raw = m.group(0)

              
                around = content[max(0, m.start()-30):m.start()]
                if 'SwingftEncryption.resolve("' in around:
                    return raw

             
                if raw not in in_contents:
                    return raw

                
                inner = raw[3:-3] if raw.startswith('"""') else raw[1:-1]
                inner_runtime = swift_unescape(inner)
                nonce = os.urandom(12)
                ct = cipher.encrypt(nonce, inner_runtime.encode(), None)
                b64 = base64.b64encode(nonce + ct).decode()
                return f'SwingftEncryption.resolve("{b64}")'

            new_content = re.sub(STRING_RE, replace_string, content)
            if new_content != content:
                with open(file_path, "w", encoding="utf-8") as f:
                    f.write(new_content)

        except Exception:
           
            pass

    count = 1 if len(swift_files) == 1 else 2 if len(swift_files) < 4 else 4
    chunk_size = 32 // count
    masks = [os.urandom(chunk_size) for _ in range(count)]
    chunks = [key[i*chunk_size:(i+1)*chunk_size if i < count-1 else 32] for i in range(count)]
    encoded_chunks = [bytes(c ^ m for c, m in zip(chunk, mask)) for chunk, mask in zip(chunks, masks)]

    
    entry_path, entry_type = patch_entry(swift_files, count)
    if not entry_path:
        return

    
    module_dir = os.path.dirname(entry_path)
    same_module_files = [f for f in swift_files if f.startswith(module_dir + os.sep)]
    preferred = [f for f in same_module_files if f != entry_path] or same_module_files or swift_files
    random.shuffle(preferred)

    used = set()
    for i in range(count):
        ef = next((p for p in preferred if p not in used), entry_path); used.add(ef)
        mf = next((p for p in preferred if p not in used), ef);        used.add(mf)
        with open(ef, "a", encoding="utf-8") as f:
            f.write(f"\nextension SwingftKey {{\n    static let encoded{i+1}: [UInt8] = [{', '.join(str(b) for b in encoded_chunks[i])}]\n}}\n")
        with open(mf, "a", encoding="utf-8") as f:
            f.write(f"\nextension SwingftKey {{\n    static let mask{i+1}: [UInt8] = [{', '.join(str(b) for b in masks[i])}]\n}}\n")

  
    insert_global_import(swift_files)
    copy_StringSecurity_folder(source_root)

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python SwingftEncryption.py <source_root> <strings.json>")
        sys.exit(1)
    encrypt_and_insert(sys.argv[1], sys.argv[2])
