import hashlib
import math
import bitarray  # Потрібно встановити: pip install bitarray


class BloomFilter:
    def __init__(self, size: int, num_hashes: int):
        self.size = size
        self.num_hashes = num_hashes
        self.bit_array = bitarray.bitarray(size)
        self.bit_array.setall(0)

    def _hashes(self, item: str):
        item = item.encode('utf-8')
        for i in range(self.num_hashes):
            # Створення хешів на основі hashlib + соль
            hash_digest = hashlib.sha256(item + str(i).encode('utf-8')).hexdigest()
            yield int(hash_digest, 16) % self.size

    def add(self, item: str):
        for hash_val in self._hashes(item):
            self.bit_array[hash_val] = 1

    def check(self, item: str) -> bool:
        return all(self.bit_array[hash_val] for hash_val in self._hashes(item))


def check_password_uniqueness(bloom: BloomFilter, passwords: list[str]) -> dict[str, str]:
    result = {}
    for password in passwords:
        if not isinstance(password, str) or password.strip() == "":
            result[password] = "некоректний"
            continue

        if bloom.check(password):
            result[password] = "вже використаний"
        else:
            result[password] = "унікальний"
            bloom.add(password)
    return result

if __name__ == "__main__":
    # Ініціалізація фільтра Блума
    bloom = BloomFilter(size=1000, num_hashes=3)

    # Додавання існуючих паролів
    existing_passwords = ["password123", "admin123", "qwerty123", "guest"]
    for password in existing_passwords:
        bloom.add(password)

    # Перевірка нових паролів
    new_passwords_to_check = ["password123", "newpassword", "admin123", "guest"]
    results = check_password_uniqueness(bloom, new_passwords_to_check)

    # Виведення результатів
    for password, status in results.items():
        print(f"Пароль '{password}' - {status}.")