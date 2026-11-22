import os
import re
import subprocess
import matplotlib.pyplot as plt
import os

files = ['1M', '5M', '10M', '25M', '50M', '75M', '100M', '250M', '500M', '750M', '1G', '2.5G']
#files = ['1M', '5M', '10M', '25M', '50M', '75M', '100M', '250M']
scripts = ['ed25519-signer', 'ml-dsa-signer', 'rsa-4096-signer']
algos = ["ml-dsa-65", "ed25519", "rsa4096-pss"]
private_keys = ['ed25519-public.pem', 'mldsa-public.pem', 'rsa4096-public.key']


def parse_size(size_str):
    size_str = size_str.strip().upper()
    multipliers = {'B': 1, 'K': 10**3, 'M': 10**6, 'G': 10**9, 'T': 10**12}
    if size_str[-1] in multipliers:
        return float(size_str[:-1]) * multipliers[size_str[-1]]
    return float(size_str)

def measure_memory(algo, file, key, times):
    pid = os.fork()
    if pid == 0:
        # дочерний процесс: глушим вывод и запускаем подписант
        fd = os.open(os.devnull, os.O_WRONLY)
        os.dup2(fd, 1)
        os.dup2(fd, 2)
        os.execv(f"./tools/verifier", f"{algo}", f"files/{file}",  f"files/{file}.{exts[algo]}", f"keys/{key}")
        os._exit(127)  # сюда попадём только если exec не удался
    _, status, usage = os.wait4(pid, 0)
    if os.waitstatus_to_exitcode(status) != 0:
        raise RuntimeError(f'{algo} завершился с ошибкой')
    return usage.ru_maxrss / 1024  # на Linux ru_maxrss в КБ


# --- Замеры ---
memory = {file: {} for file in files}
for file in files:
    for algo, key in zip(["ml-dsa-65", "ed25519", "rsa4096-pss"], private_keys):
        memory[file][algo] = measure_memory(algo, file, key, memory)
        print(f'{algo:16} {file:>5}: {memory[file][algo]:8.2f} МБ')

# --- График ---
plt.figure(figsize=(10, 6))
for algo in algos:
    x = [parse_size(f) for f in files]
    y = [memory[f][algo] for f in files]
    plt.plot(x, y, marker='o', label=algo)

plt.xlabel('Размер файла (байты)')
plt.ylabel('Пиковое потребление RAM (МБ)')
plt.title('Потребление памяти в зависимости от размера файла')
plt.legend()
plt.grid(True)
plt.tight_layout()
plt.savefig('memory_usage.png', dpi=150)
plt.show()