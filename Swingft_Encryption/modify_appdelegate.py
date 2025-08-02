import os
import re
import sys
import shutil
def find_appdelegate_file(project_path):
    for root, _, files in os.walk(project_path):
        for file in files:
            if file == 'AppDelegate.swift':
                return os.path.join(root, file)
    return None

def find_class_bounds(lines, class_index):
    brace_count = 0
    for i in range(class_index, len(lines)):
        brace_count += lines[i].count('{')
        brace_count -= lines[i].count('}')
        if brace_count == 0:
            return i
    return len(lines) - 1
    
def find_project_root(start_path):
    for root, dirs, _ in os.walk(start_path):
        for d in dirs:
            if d.endswith(".xcodeproj") or d.endswith(".xcworkspace"):
                return os.path.join(root, d)
    return None

def copy_stringsecurity_package(source_path, dest_root):
    dest_path = os.path.join(dest_root, "StringSecurity")
    if os.path.exists(dest_path):
        print(f"기존 StringSecurity 폴더가 이미 존재합니다: {dest_path}")
        return
    shutil.copytree(source_path, dest_path)
    print(f"StringSecurity 복사 완료: {dest_path}")
    
def insert_import_if_missing(lines):
    for line in lines:
        if line.strip() == 'import StringSecurity':
            return lines
    for i, line in enumerate(lines):
        if line.startswith('import '):
            continue
        lines.insert(i, 'import StringSecurity\n')
        break
    return lines

def find_main_attribute(lines):
    for i, line in enumerate(lines):
        if line.strip().startswith('@main'):
            return i
    return None

def process_appdelegate(filepath):
    with open(filepath, 'r', encoding='utf-8') as f:
        lines = f.readlines()

    lines = insert_import_if_missing(lines)

    main_index = find_main_attribute(lines)
    combined_key_func = '''enum SwingftKey {
    static func combinedKey() -> Data {
        var key = [UInt8]()

        let encodedParts: [[UInt8]] = [
            encoded1,
            encoded2
        ]
        let maskParts: [[UInt8]] = [
            mask1,
            mask2
        ]

        if let _ = try? encoded3, let _ = try? mask3 {
            
            let ep: [[UInt8]] = [encoded1, encoded2, encoded3, encoded4]
            let mp: [[UInt8]] = [mask1, mask2, mask3, mask4]
            for swingft1 in 0..<ep.count {
                for swingft2 in 0..<ep[swingft1].count {
                    key.append(ep[swingft1][swingft2] ^ mp[swingft1][swingft2])
                }
            }
        } else {
            for swingft1 in 0..<2 {
                for swingft2 in 0..<encodedParts[swingft1].count {
                    key.append(encodedParts[swingft1][swingft2] ^ maskParts[swingft1][swingft2])
                }
            }
        }

        return Data(key)
    }
}
'''

    if main_index is not None:
        lines.insert(main_index, combined_key_func + '\n')
    else:
        lines.insert(0, combined_key_func + '\n')

    class_pattern = re.compile(r'class\s+AppDelegate\s*:\s*UIResponder\s*,\s*UIApplicationDelegate\s*{')
    method_pattern = re.compile(r'func\s+application\(\s*_ application:\s*UIApplication\s*,\s*didFinishLaunchingWithOptions.*\)\s*->\s*Bool\s*{')

    class_index = -1
    method_index = -1

    for i, line in enumerate(lines):
        if class_index == -1 and class_pattern.search(line):
            class_index = i
        if method_index == -1 and method_pattern.search(line):
            method_index = i

    if class_index == -1:
        print("AppDelegate 클래스가 없습니다.")
        return

    class_end = find_class_bounds(lines, class_index)

    new_method_lines = [
        '    func application(_ application: UIApplication, didFinishLaunchingWithOptions launchOptions: [UIApplication.LaunchOptionsKey: Any]?) -> Bool {\n',
        '        let key = SwingftKey.combinedKey()\n',
        '        SwingftEncryption.configure(key: key)\n',
        '        return true\n',
        '    }\n'
    ]

    if method_index != -1:
        brace_count = 0
        inserted = False
        for i in range(method_index, len(lines)):
            if '{' in lines[i]:
                brace_count += lines[i].count('{')
            if '}' in lines[i]:
                brace_count -= lines[i].count('}')
            if brace_count > 0 and not inserted:
                insert_line = i + 1
                lines.insert(insert_line, '        let key = SwingftKey.combinedKey()\n')
                lines.insert(insert_line + 1, '        SwingftEncryption.configure(key: key)\n')
                inserted = True
                break
    else:
        lines[class_end:class_end] = ['\n'] + new_method_lines

    with open(filepath, 'w', encoding='utf-8') as f:
        f.writelines(lines)

    #print(f"AppDelegate.swift 수정 완료: {filepath}")

def main():
    if len(sys.argv) != 2:
        print("사용법: python modify_appdelegate.py <Swift_프로젝트_경로>")
        return

    project_root = sys.argv[1]

    xcode_path = find_project_root(project_root)
    if not xcode_path:
        print(" .xcodeproj 또는 .xcworkspace를 찾을 수 없습니다.")
        return

    xcode_root = os.path.dirname(xcode_path)

    current_dir = os.path.dirname(os.path.abspath(__file__))
    stringsecurity_src = os.path.join(current_dir, "StringSecurity")

    if not os.path.isdir(stringsecurity_src):
        print(f"현재 디렉토리에 StringSecurity 폴더가 없습니다: {stringsecurity_src}")
        return

    copy_stringsecurity_package(stringsecurity_src, xcode_root)

    appdelegate_path = find_appdelegate_file(project_root)
    if not appdelegate_path:
        print("AppDelegate.swift 파일을 찾을 수 없습니다.")
        return

    process_appdelegate(appdelegate_path)


if __name__ == '__main__':
    main()

