import subprocess

result = subprocess.run(["pacman", "-Q"], capture_output = True, text = True)
lines = result.stdout.splitlines()

packages = {}
for line in lines:
    name, version = line.split()
    packages[name] = version

print(f"You have {len(lines)} packages installed.")
print("konsole version:", packages.get("konsole"))