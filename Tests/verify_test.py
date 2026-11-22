import time
import subprocess
import matplotlib.pyplot as plt

files = ['1M', '5M', '10M', '25M', '50M', '75M', '100M', '250M', '500M', '750M', '1G', '2.5G']
#files = ['1M', '5M', '10M', '25M', '50M', '75M', '100M', '250M']
scripts = ['ed25519-signer', 'ml-dsa-signer', 'rsa-4096-signer']
algos = ["ml-dsa-65", "ed25519", "rsa4096-pss"]
private_keys = ['ed25519-public.pem', 'mldsa-public.pem', 'rsa4096-public.key']


def parse_size(size_str):
    """Преобразует строку размера ('1M', '2.5G') в байты."""
    size_str = size_str.strip().upper()
    multipliers = {'B': 1, 'K': 10**3, 'M': 10**6, 'G': 10**9, 'T': 10**12}
    if size_str[-1] in multipliers:
        return float(size_str[:-1]) * multipliers[size_str[-1]]
    return float(size_str)


def measure_time(algo, file, key, times):
    print(f"Measuring time for {algo} on file {file} with key {key}...")
    exts = {
        'ml-dsa-65': 'mldsa',
        'ed25519': 'ed25519',
        'rsa4096-pss': 'rsa4096'
    }
    start = time.time()
    result = subprocess.run(
        [f"./tools/verifier", f"{algo}", f"files/{file}",  f"files/{file}.{exts[algo]}", f"keys/{key}"],
        capture_output=True, text=True
    )
    duration = time.time() - start
    times[file][algo] = duration


# --- Замеры ---
times = {file: {} for file in files}
for file in files:
    for algo, key in zip(["ml-dsa-65", "ed25519", "rsa4096-pss"], private_keys):
        measure_time(algo=algo, file=file, key=key, times=times)  # <-- было file=files


# --- Построение графика ---
plt.figure(figsize=(10, 6))

for algo in algos:
    x = [parse_size(f) for f in files]
    y = [times[f][algo] for f in files]
    plt.plot(x, y, marker='o', label=algo)

plt.xlabel('Размер файла (байты)')
plt.ylabel('Время проверки (секунды)')
plt.title('Время проверки в зависимости от размера файла')
plt.legend()
plt.grid(True)

# Опционально: логарифмическая шкала по X — удобно, когда размеры сильно различаются
# plt.xscale('log')

plt.tight_layout()
plt.savefig('verify_time.png', dpi=150)  # сохранит картинку рядом со скриптом
plt.show()