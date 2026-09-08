import math
import hashlib

class Welford:
    """
    Computes running mean and variance incrementally.
    """
    def __init__(self):
        self.count = 0
        self.mean = 0.0
        self.m2 = 0.0

    def update(self, value):
        self.count += 1
        delta = value - self.mean
        self.mean += delta / self.count
        delta2 = value - self.mean
        self.m2 += delta * delta2

    def get_variance(self):
        if self.count < 2:
            return 0.0
        return self.m2 / (self.count - 1)

    def get_stddev(self):
        return math.sqrt(self.get_variance())


class CountMinSketch:
    """
    Basic Count-Min Sketch for tracking frequencies / approximate entropy incrementally.
    """
    def __init__(self, width=256, depth=4):
        self.width = width
        self.depth = depth
        self.table = [[0] * width for _ in range(depth)]
        self.total_count = 0

    def _hash(self, item, seed):
        # Using md5 for simplicity without external dependencies
        m = hashlib.md5()
        m.update(str(seed).encode('utf-8'))
        m.update(str(item).encode('utf-8'))
        return int(m.hexdigest(), 16) % self.width

    def add(self, item, count=1):
        self.total_count += count
        for i in range(self.depth):
            idx = self._hash(item, i)
            self.table[i][idx] += count

    def get(self, item):
        min_count = float('inf')
        for i in range(self.depth):
            idx = self._hash(item, i)
            min_count = min(min_count, self.table[i][idx])
        return min_count

    def approximate_entropy(self):
        """
        Approximates Shannon entropy based on the CMS frequencies.
        Note: This is an upper-bound approximation in CMS.
        """
        if self.total_count == 0:
            return 0.0
        
        entropy = 0.0
        # To avoid scanning massive keyspaces, one heuristic is summing the row
        # entropies and taking the min or average, or tracking top-K.
        # For a small width, we iterate over a row (using row 0 as a rough proxy)
        for count in self.table[0]:
            if count > 0:
                p = count / self.total_count
                entropy -= p * math.log2(p)
        return entropy


class EWMA:
    """
    Exponentially Weighted Moving Average for tracking baseline drifts.
    """
    def __init__(self, alpha=0.1):
        self.alpha = alpha
        self.value = None

    def update(self, new_value):
        if self.value is None:
            self.value = new_value
        else:
            self.value = (self.alpha * new_value) + (1 - self.alpha) * self.value
        return self.value

    def get(self):
        return self.value if self.value is not None else 0.0
