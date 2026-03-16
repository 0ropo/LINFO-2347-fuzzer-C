import subprocess

for i in range(6):
    bug = f"bugs/bug{i}"
    print(f"\n=== {bug} ===\n")
    r = subprocess.run(["./fuzzer", bug], capture_output=True, text=True)
    print("Return code:", r.returncode)
    print("\nSTDOUT:\n")
    print(r.stdout)
    print("\nSTDERR:\n")
    print(r.stderr)
