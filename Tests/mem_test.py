import os
import re
import subprocess
import matplotlib.pyplot as plt
import os

files = ['1M', '5M', '10M', '25M', '50M', '75M', '100M', '250M', '500M', '750M', '1G', '2.5G']
scripts = ['ml-dsa-signer', 'ed25519-signer', 'rsa-4096-signer']
private_keys = ['mldsa-private.pem', 'ed25519-private.pem', 'rsa4096-private.key']


def parse_size(size_str):
    size_str = size_str.strip().upper()
    multipliers = {'B': 1, 'K': 10**3, 'M': 10**6, 'G': 10**9, 'T': 10**12}
    if size_str[-1] in multipliers:
        return float(size_str[:-1]) * multipliers[size_str[-1]]
    return float(size_str)

def measure_memory(script, file, key):
    pid = os.fork()
    if pid == 0:
        # дочерний процесс: глушим вывод и запускаем подписант
        fd = os.open(os.devnull, os.O_WRONLY)
        os.dup2(fd, 1)
        os.dup2(fd, 2)
        os.execv(f'./tools/{script}', [script, f'files/{file}', f'keys/{key}'])
        os._exit(127)  # сюда попадём только если exec не удался
    _, status, usage = os.wait4(pid, 0)
    if os.waitstatus_to_exitcode(status) != 0:
        raise RuntimeError(f'{script} завершился с ошибкой')
    return usage.ru_maxrss / 1024  # на Linux ru_maxrss в КБ


# --- Замеры ---
memory = {file: {} for file in files}
for file in files:
    for script, key in zip(scripts, private_keys):
        memory[file][script] = measure_memory(script, file, key)
        print(f'{script:16} {file:>5}: {memory[file][script]:8.2f} МБ')

# --- График ---
plt.figure(figsize=(10, 6))
for script in scripts:
    x = [parse_size(f) for f in files]
    y = [memory[f][script] for f in files]
    plt.plot(x, y, marker='o', label=script)

plt.xlabel('Размер файла (байты)')
plt.ylabel('Пиковое потребление RAM (МБ)')
plt.title('Потребление памяти в зависимости от размера файла')
plt.legend()
plt.grid(True)
plt.tight_layout()
plt.savefig('memory_usage.png', dpi=150)
plt.show()