from .meta import LOWER, UPPER

class SampleDecrypt:
    def __init__(self, offset: int = 3):
        self.offset = offset
        self.lower = LOWER
        self.upper = UPPER

    def decrypt(self, cipher_text: str) -> str:
        result = ""
        for char in cipher_text:
            if char in self.lower:
                idx = self.lower.index(char)
                new_idx = (idx - self.offset) % 26
                result += self.lower[new_idx]
            elif char in self.upper:
                idx = self.upper.index(char)
                new_idx = (idx - self.offset) % 26
                result += self.upper[new_idx]
            else:
                result += char
        return result