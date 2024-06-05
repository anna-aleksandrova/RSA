"""The module is designed for generating RSA keypairs.
"""
import asn_1 # type: ignore
import random
import time
import sys
sys.setrecursionlimit(20000)

def gcd(a, b):
    """Finds the gcd(a, b).

    Args:
        a (int): Positive integer.
        b (int): Positive integer.
    
    Returns:
        res (int): The gcd of a and b.
    """
    while True:
        r = a % b
        if r == 0:
            return b
        else:
            a = b
            b = r

def gcd_extended(a, b):
    """Finds d = gcd(a, b) and linear combination of <a> and <b> such that
        x * a + y * b = 1.
    
    Args:
        a (int): The first integer.
        b (int): The second integer.
    
    Returns:
        x (int): <a> coefficient.
        y (int): <b> coefficient.
        gcd (int): The greatest common divisor of <a> and <b>.
    """
    if a == 0:
        return 0, 1, b
    else:
        x1, y1, gcd = gcd_extended(b % a, a)
        x = y1 - (b // a) * x1
        y = x1
        return x, y, gcd

def coprime(n, domain):
    """Generates random coprime to <n> from the given domain.

    Args:
        n (int, base10): A number to generate coprime to.
        domain (tuple): domain[0] = start, domain[1] = stop; stop is not included.

    Returns:
        a (int, base10): Random coprime to <n>. 
    """
    if  not (isinstance(domain, tuple) and len(domain) == 2 and isinstance(domain[0], int) 
                and isinstance(domain[1], int)):
        raise ValueError(f"{domain} can't be considered as a domain to take values from.")
    while True:
        a = random.randrange(domain[0], domain[1])
        if gcd(n, a) == 1:
            return a
        else:
            pass

def miller_rabin(n, witnesses = 4):
    """Checks whether a number is prime. Uses Miller-Rabin test.

    Args:
        n (int): A number in base10 to check.
        witnesses (int): An amount of numbers which "witness" <n> being prime.
      
    Returns:
        value (bool): True, if <n> is prime. False otherwise.
    """
    if n == 2:
        return True
    elif n % 2 == 0:
        return False
    else:
        for i in range(witnesses):
            base = coprime(n, (2, n - 1))
            N = n - 1
            k = 0
            while True:
                if N % 2 == 0:
                    N //= 2
                    k += 1
                else:
                    m = N
                    break
            temp = pow(base, m, n)
            if temp == 1 or temp == n - 1:
                return True
            for i in range(k):
                temp = pow(temp, 2, n)
                if temp == n - 1:
                    return True
                elif temp == 1:
                    return False
                else:
                    pass
        return False
 
def generate(bits_amount):
    """Generates a prime number of the given amount of bits.

    Args:
        bits_amount (int): An amount of bits.

    Returns:
        n (int): A generated number (base 10) which satisfies the requirements.
    """
    n = "1"
    for i in range(bits_amount - 1):
        n += str(random.randrange(2))
    n = asn_1.decimal(n)
    while True:
        if miller_rabin(n):
            return n
        else:
            n += 1

def inverse(e, phi_n):
    """Finds the multiplicative inverse of <e> modulo <phi_n>.
    Uses extended Euclidean algorithm.

    Args:
        e (int): A public exponent.
        phi_n (int): The value of Euler's function from argument <p * q>.
        
    Returns:
        inverse (int): The multiplicative inverse.
    """
    return gcd_extended(phi_n, e)[1] % phi_n

class Keypair:
    """RSA keypair, thus a pair of public and private keys.

    Attributes:
        _public (PublicKey): Public key.
        _private (PrivateKey): Private key.
    """
    id = 0

    def __init__(self, bits):
        print("Generating public/private rsa key pair...")
        self._private = PrivateKey(bits)
        self._public = PublicKey(self._private)
        self._id = Keypair.id
        Keypair.id += 1
        print("Generating public/private rsa key pair finished.")

    def write_into(self, filename1, filename2):
        """Writes <self._public> into file <filename1>.
            Writes <self._private> into file <filename2>.
        """
        self._public.write_into(filename1)
        self._private.write_into(filename2)

class PrivateKey:
    """Represents the private key from RSA keypair.

    Attributes: 
        p (int): The first prime factor, positive integer.
        q (int): The second prime factor, positive integer.
        N (int): The product of p and q.
        e (int): A positive integer, coprime to phi(N) = (p - 1) * (q - 1)
                    as long as <p> and <q> are both primes.
        d (int): A multiplicative inverse of <e> modulo phi(N).
    """
    def __init__(self, bits, otherPrimeInfos=None):
        """Initializes an RSA private key.

        Args:
            bits (int): An amount of bits which <self.p> and <self.q>
                          will have in their binary representation.
        """
        self.p = generate(bits)
        self.q = generate(bits)
        self.n = self.p * self.q
        self.e = coprime((self.p - 1) * (self.q - 1), (max(self.p, self.q) + 1, self.n))
        self.d = inverse(self.e, (self.p - 1) * (self.q - 1))
        self.exp1 = self.d % (self.p - 1)
        self.exp2 = self.d % (self.q - 1)
        self.coefficient = inverse(self.q, self.p)
        self.otherPrimeInfos = otherPrimeInfos
    
    def as_asn1(self):
        if self.otherPrimeInfos is not None:
            version = 1
        else:
            version = 0
        return asn_1.SEQUENCE(
            asn_1.INTEGER(version),
            asn_1.INTEGER(self.n),
            asn_1.INTEGER(self.e),
            asn_1.INTEGER(self.d),
            asn_1.INTEGER(self.p),
            asn_1.INTEGER(self.q),
            asn_1.INTEGER(self.exp1),
            asn_1.INTEGER(self.exp2),
            asn_1.INTEGER(self.coefficient)
        )

    def as_der(self):
        return self.as_asn1().der()

    def write_into(self, filename):
        with open(filename, "w") as private:
            private.write("-----BEGIN RSA PRIVATE KEY-----\n")
            data = self.as_asn1().base64()
            for i in range(len(data) // 70):
                private.write(data[i * 70 : (i + 1) * 70] + '\n')
            private.write(data[70 * (len(data) // 70):])
            private.write("\n-----END RSA PRIVATE KEY-----")
        print(f"Your identification has been saved in {filename}")

    @classmethod
    def read_from(cls, filename):
        with open(filename, 'r') as f:
            key = f.read().replace("-----BEGIN RSA PRIVATE KEY-----\n", "").replace("-----END RSA PRIVATE KEY-----", "").replace("\n", "")
            res = asn_1.analyze(key)
            return asn_1.analyze(key)

class PublicKey:
    """Represents a public key from RSA keypair.

    Attributes:
        N (int): A public constant (modulus).
        e (int): A public exponent.
    """
    def __init__(self, other):
        """Initializes a public key.

        Args:
            other (PrivateKey): A private key which will be represented by <self>.
        """
        self.n = other.p * other.q
        self.e = other.e

    def as_asn1(self):
        return asn_1.SEQUENCE(
            asn_1.INTEGER(self.n),
            asn_1.INTEGER(self.e)
        )

    def as_der(self):
        return self.as_asn1().der()
    
    def write_into(self, filename):
        with open(filename, "w") as public:
            public.write("-----BEGIN RSA PUBLIC KEY-----\n")
            data = self.as_asn1().base64()
            for i in range(len(data) // 70):
                public.write(data[i * 70 : (i + 1) * 70] + '\n')
            public.write(data[70 * (len(data) // 70):])
            public.write("\n-----END RSA PUBLIC KEY-----")
        print(f"Your public key has been saved in {filename}")
    
    @classmethod
    def read_from(cls, filename):
        with open(filename, 'r') as f:
            key = f.read().replace("-----BEGIN RSA PUBLIC KEY-----\n", "").replace("-----END RSA PUBLIC KEY-----", "").replace("\n", "")
            return asn_1.analyze(key)
