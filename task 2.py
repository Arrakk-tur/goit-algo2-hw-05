import time
import re
import mmh3
import math
from typing import List
from pathlib import Path
from tabulate import tabulate


class HyperLogLog:
    def __init__(self, p=14):
        self.p = p
        self.m = 1 << p
        self.registers = [0] * self.m
        self.alpha = self._get_alpha()
        self.small_range_correction = 5 * self.m / 2

    def _get_alpha(self):
        if self.p == 4:
            return 0.673
        elif self.p == 5:
            return 0.697
        elif self.p == 6:
            return 0.709
        else:
            return 0.7213 / (1 + 1.079 / self.m)

    def _rho(self, w):
        return len(bin(w)) - bin(w).rfind("1")

    def add(self, item):
        x = mmh3.hash(str(item), signed=False)
        j = x & (self.m - 1)
        w = x >> self.p
        self.registers[j] = max(self.registers[j], self._rho(w))

    def count(self):
        Z = sum(2.0 ** -r for r in self.registers)
        E = self.alpha * self.m * self.m / Z

        if E <= self.small_range_correction:
            V = self.registers.count(0)
            if V > 0:
                return self.m * math.log(self.m / V)

        return E


def load_ip_addresses(filepath: str) -> List[str]:
    ip_regex = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
    ip_list = []

    with open(filepath, 'r', encoding='utf-8', errors='ignore') as file:
        for line in file:
            match = ip_regex.search(line)
            if match:
                ip_list.append(match.group())

    return ip_list


def exact_count(ip_list: List[str]) -> int:
    return len(set(ip_list))


def hll_count(ip_list: List[str], p=14) -> float:
    hll = HyperLogLog(p=p)
    for ip in ip_list:
        hll.add(ip)
    return hll.count()


def main():
    log_file = "lms-stage-access.log"
    if not Path(log_file).exists():
        print(f"Файл не знайдено: {log_file}")
        return

    print("Завантаження IP-адрес...")
    ip_list = load_ip_addresses(log_file)
    print(f"Загальна кількість записів з IP: {len(ip_list)}")

    # Точний підрахунок
    start_exact = time.time()
    exact = exact_count(ip_list)
    end_exact = time.time()

    # HyperLogLog підрахунок
    start_hll = time.time()
    approx = hll_count(ip_list, p=14)
    end_hll = time.time()

    # Результати
    table = [
        ["Унікальні елементи", f"{exact:.1f}", f"{approx:.1f}"],
        ["Час виконання (сек.)", f"{end_exact - start_exact:.3f}", f"{end_hll - start_hll:.3f}"],
    ]
    print("\nРезультати порівняння:")
    print(tabulate(table, headers=["", "Точний підрахунок", "HyperLogLog"], tablefmt="grid"))


if __name__ == "__main__":
    main()