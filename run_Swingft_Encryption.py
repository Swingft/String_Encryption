import sys, os, re, subprocess, shutil, pathlib

JSON_SAVED_RE = re.compile(r"JSON saved to (.+)$")

def die(msg, code=1):
    print(f"[ERR] {msg}", file=sys.stderr)
    sys.exit(code)

def find_package_root(start):
    start = pathlib.Path(start).resolve()
    for cur in [start] + list(start.parents):
        if (cur / "Package.swift").exists():
            return cur
    return None

def main():
  
    if len(sys.argv) != 3:
        print("Usage: python3 run_Swingft_Encryption.py <ProjectRootPath> <ConfigPath>", file=sys.stderr)
        sys.exit(1)

    project_root = sys.argv[1]
    config_json  = sys.argv[2]

    if shutil.which("swift") is None:
        die("'swift' 명령을 찾을 수 없습니다. Xcode/Swift 설치를 확인하세요.")

    wrapper_dir = pathlib.Path(__file__).resolve().parent
    package_dir = find_package_root(wrapper_dir) or find_package_root(os.getcwd())
    if package_dir is None:
        die("run_Swingft_Encryption.py를 Swift 패키지 루트에 두세요.")

    py_script = wrapper_dir / "SwingftEncryption.py"
    if not py_script.exists():
        alt = package_dir / "SwingftEncryption.py"
        if alt.exists():
            py_script = alt
        else:
            die(f"SwingftEncryption.py가 없습니다: {py_script}")

    
    cmd_swift = ["swift", "run", "Swingft_Encryption", project_root, config_json]
    print(f"[RUN] {' '.join(cmd_swift)} (cwd={package_dir})")
    proc = subprocess.run(cmd_swift, cwd=str(package_dir), text=True, capture_output=True)

   
    if proc.stdout:
         sys.stdout.write(proc.stdout)
    if proc.stderr:
        sys.stderr.write(proc.stderr)

    if proc.returncode != 0:
        die(f"swift run 실패 (exit {proc.returncode})", proc.returncode)

    
    m = None
    for line in (proc.stdout or "").splitlines():
        m = JSON_SAVED_RE.search(line)
        if m:
            break
    strings_path = pathlib.Path(m.group(1)).expanduser() if m else (package_dir / "strings.json")
    if not strings_path.exists():
        die(f"strings.json을 찾지 못했습니다: {strings_path}", 2)


    cmd_py = [sys.executable, str(py_script),
              str(pathlib.Path(project_root).resolve()),
              str(strings_path.resolve())]
    print(f"[RUN] {' '.join(cmd_py)} (cwd={py_script.parent})")
    p2 = subprocess.run(cmd_py, cwd=str(py_script.parent))
    if p2.returncode != 0:
        die(f"SwingftEncryption.py 실패 (exit {p2.returncode})", p2.returncode)

    print("[Swingft_String_Encryption] 전체 파이프라인 완료")

if __name__ == "__main__":
    main()
