from abc import ABCMeta, abstractmethod

def _binary(n):
    """Generates digits for binary representation of <n>.

    Args:
        n (int, str): An integer in base 10.

    Yields:
        digit (int): 1 xor 0 (the first one is the rightmost in binary representation,
                      the last one is the leftmost in binary representation).
    """
    if isinstance(n, str):
        n = int(n)
    while n > 0:
        temp = n % 2
        n //= 2
        if temp == 0:
            yield 0
        else:
            yield 1

def binary(n):
    """Binary representation of a number <n> given in base 10.

    Args:
        n (int, str): An integer in base 10.
    
    Returns:
        res (str): <n> in binary.    
    """
    res = ""
    for digit in _binary(n):
        res = str(digit) + res
    return res

def binary_extended(n):
    """Extended (to 6 bits) binary representation of a number <n> given in base 10.
    Note: it must be non-negative number not greater than 63.

    Args:
        n (int, str): An integer in base 10.
    
    Returns:
        n (str): <n> in binary, length = 6. 

    Raises:
        ValueError: If <n> is not from domain [0:64] 
    """
    if isinstance(n, str):
        n = int(n)
    if n < 0 or n >= 64:
        raise ValueError(f"Can't apply this function to the number {n}: not from domain [0:64]")
    n = binary(n)
    n = "0" * (6 - len(n)) + n
    return n

def is_binary(obj):
    """Checks whether <obj> can be considered as
        a binary representation of another object.
    
    Args:
        obj (str, int): An object to be checked.
    
    Returns:
        res (bool): True if <obj> can be considered as a binary representation,
                    False otherwise.

    Raises:
        ValueError: If <obj> not of type <str> and not of type <int> was passed in.
    """
    if isinstance(obj, int):
        obj = str(obj)
    elif isinstance(obj, str):
        pass
    else:
        raise ValueError(f"An object of {type(obj)} can't be checked.")
    check = True
    for symbol in obj:
        if symbol != "0" and symbol != "1":
            check = False
            break
        else:
            pass
    return check

def _hex(n):
    """Generates digits for hexadecimal representation of <n>.

    Args:
        n (int/str): An integer in base 2.

    Yields:
        digit (str): One at a time from "0123456789ABCDEF" (the first one is the rightmost
                      in hexadecimal representation, the last one is the leftmost in hexadecimal
                      representation).
    """
    if isinstance(n, str):
        n = int(n)
    HEX = "0123456789ABCDEF"
    while n:
        temp = n % 10 ** 4
        n //= 10 ** 4
        res = 0
        i = 0
        while temp:
            res += temp % 10 * 2 ** i
            temp //= 10
            i += 1
        yield HEX[res]

def hex(n):
    """Hexadecimal representation of a number <n> in base 2.

    Args:
        n (int, str): An integer in base 2.
    
    Returns:
        res (str): <n> in hex.    
    """
    res = ""
    for digit in _hex(n):
        res = digit + res
    if len(res) < 2:
        res = "0" * (2 - len(res)) + res
    return res

hex_decode = {
    **{f"{i}": i for i in range(10)},
    "A": 10,
    "B": 11,
    "C": 12,
    "D": 13,
    "E": 14,
    "F": 15
}

def hex_binary(n):
    """
    Binary representation of a number <n> in base 16.

    Args:
        n (str): An integer in base 16.
    
    Returns:
        res (str): <n> in binary.    
    """
    res = ""
    for i in range(len(n)):
        temp = binary(hex_decode[n[i]])
        if len(temp) < 4:
            temp = "0" * (4 - len(temp)) + temp
        res += temp
    return res

def decimal(n):
    """
    Decimal representation of a number <n> given in base2.

    Args:
        n (str): An integer in base 2.
    
    Returns:
        res (int): <n> in decimal.    
    """
    res = 0
    n = n[::-1]
    for i in range(len(n)):
        res += 2**i * int(n[i])
    return res

capital = {i: chr(65 + i) for i in range(26)}
lower = {j + 26: chr(97 + j) for j in range(26)}
numbers = {k + 52: chr(48 + k) for k in range(10)}
additional = {
    62: "+",
    63: "/"
}
base64 = {**capital, **lower, **numbers, **additional}

from_base64 = {}
for key, value in base64.items():
    from_base64[value] = key


def _decode(string):
    """Decodes a string in base64 into bytes (generates sequences of bytes).

    Args:
        string (str): A string in base64.
    
    Yields:
        res (str): 3 bytes which correspond to the 4 characters at a time.
    """
    res = ""
    for i in range(len(string) // 4):
        block = string[i*4 : (i+1)*4]
        bit_string = ""
        for digit in block:
            if digit != "=":
                bit_string += binary_extended(from_base64[digit])
            else:
                pass
        if len(bit_string) == 18:
            k = 2
        elif len(bit_string) == 12:
            k = 1
        else:
            k = 3
        for j in range(k):
            byte = bit_string[j*8 : (j+1)*8]
            res += hex(byte) + " "
    yield res[:-1:]

def decode(string):
    """Decodes a string in base64 into bytes.

    Args:
        string (str): A string in base64.
    
    Returns:
        res (str): Byte representation of <string>.
    """
    res = ""
    for sequence in _decode(string):
        res += sequence + " "
    return res[:-1:]

def analyze(obj):
    """Analyzes the <sobj>. Considers TLS-encoding (type-length-value). 
        Only <INTEGER> and <SEQUENCE> are considered as types.

    Args:
        obj (str / list): ASN_1 object (either INTEGER or SEQUENCE) encoded in base64
                            (basically, valid base64 string).
    
    Returns:
        A structure, encoded in ASN_1
    """
    if isinstance(obj, list):
        tokens = obj
    else:
        tokens = decode(obj).split()
    if tokens[0] == "02":
        type_ = "INTEGER"
    elif tokens[0] == "30":
        type_ = "SEQUENCE"
    else:
        raise ValueError(f"Unconsidered tag -> can't define the type. Expected: '02' or '30', got: {tokens[0]}")
    
    length = hex_binary(tokens[1])
    if length[0] == '1':
        next = decimal(length[1:])
        length = ""
        for i in range(next):
            length += hex_binary(tokens[2 + i])
        length = decimal(length)
    elif length[0] == '0':
        next = 0
        length = decimal(length[1:])
    else:
        raise ValueError(f"Unconsidered length -> can't define the length. Expected: '0<...>' or '1<...>', got: {tokens[1]}")
    
    if type_ == "INTEGER":
        value_binary = ""
        bytes = tokens[2 + next : 2 + next + length]
        for byte in bytes:
            value_binary += hex_binary(byte)
        value = decimal(value_binary)
        if len(bytes) + 2 + next < len(tokens):
            rest = analyze(tokens[2 + next + length :])
            if isinstance(rest, tuple):
                return INTEGER(value), *rest
            else:
                return INTEGER(value), rest
        else:
            return INTEGER(value)
        
    elif type_ == "SEQUENCE":
        value = tokens[2 + next : 2 + next + length]
        if len(value) + 2 + next < len(tokens):
            rest = analyze(tokens[2 + next + length :])
            if isinstance(rest, tuple):
                return SEQUENCE(*analyze(value)), *rest
            else:
                return SEQUENCE(*analyze(value)), rest
        else:
            temp = analyze((value))
            if isinstance(temp, INTEGER):
                return SEQUENCE(temp)
            else:
                return SEQUENCE(*temp)
    else:
        raise ValueError(f"Undefined type -> can't define the value. Expected: '02' or '30', got: {tokens[0]}")

TAG = {
    "INTEGER": "02",
    "SEQUENCE": "30"
}

class ASN1_primitive(metaclass = ABCMeta):
    """Represents some structure from ASN_1.

    Attributes:
        length (int): An amount of bytes which is needed to encode
                        <object>'s value in DER.
        value (int): A value of integer.
    """    

    @classmethod
    def der_integer(cls, n):
        """Returns representation of <n>'s value constructed according to DER rules.

        Args:
            n (int): A number to encode (non-negative).

        Returns:
            octets (str): An ordered sequence of bytes.
        """

        binary_repr = binary(n)
        remainder = len(binary_repr) % 8
        binary_repr = '0' * (8 - remainder) + binary_repr
        if binary_repr[0] == '1':
            padding = '0' * 8
            binary_repr += padding

        octets = ""
        for i in range(len(binary_repr) // 8):
            aux = hex(str(binary_repr[i * 8 : (i + 1) * 8]))
            if len(aux) == 0:
                octets += "00 "
            elif len(aux) == 1:
                octets += "0" + aux + " "
            else:
                octets += aux + " "
        return octets[:-1:]
    
    @classmethod
    def _length(cls, byte_string):
        """Encodes the length of the <byte_string>, which is a binary representation
            of some integer.
        
        Args:
            byte_string (str): A string which contains bytes as binary octets splitted
                                by the whitespace.
        
        Returns:
            res (str): The length in base16 (hex) encoded accordingly to DER
                            (long length is considered: when length of the value >= 128).
        """
        len_decimal = len(byte_string.split())
        if len_decimal <= 127:
            res = hex(binary(len_decimal))
        else:
            aux = ASN1_primitive.der_integer(len_decimal)
            temp = binary(len(aux.split()))
            main_binary = "1" + "0" * (7 - len(temp)) + temp
            res =  hex(main_binary) + " " + aux
        if len(res) == 1:
                res = "0" + res
        else:
            pass
        return res

    def __init__(self, value, type = None, length = None):
        self.value = value
        if isinstance(value, tuple):
            temp = ""
            for integer in value:
                temp += integer.der() + " "
            self.length = ASN1_primitive._length(temp)
        else:
            self.length = ASN1_primitive._length(ASN1_primitive.der_integer(value))

    @abstractmethod
    def der(self):
        pass

    def base64(self):
        """Returns <self> encoded in base64 as a string.
        """
        from_ = self.der().split()
        res = ""
        for i in range(len(from_) // 3):
            block = from_[i*3 : (i + 1)*3]
            temp = ""
            for byte in block:
                temp += hex_binary(byte)
            for j in range(4):
                six_bits = temp[j*6: (j + 1) * 6]
                res += base64[decimal(six_bits)]
        if len(from_) % 3 != 0:
            remainder = len(from_) % 3
            block = from_[-remainder:]
            temp = ""
            for byte in block:
                temp += hex_binary(byte)
            temp += "0" * (6 - len(temp) % 6)
            if len(temp) == 12:
                for j in range(2):
                    six_bits = temp[j*6: (j + 1) * 6]
                    res += base64[decimal(six_bits)]
                res += "=="
            elif len(temp) == 18:
                for j in range(3):
                    six_bits = temp[j * 6: (j + 1) * 6]
                    res += base64[decimal(six_bits)]
                res += "="
            else:
                pass
        else:
            pass
        return res


class INTEGER(ASN1_primitive):
    """Represents a basic type of ASN_1: INTEGER.

    Attributes:
        type (str): A type of an object; class variable.
        length (int): An amount of bytes which is needed to encode
                        <object>'s value in DER.
        value (int): A value of integer.
    """
    type = "INTEGER"

    def __init__(self, value, type=None, length = None):
        super().__init__(value)
        self.tag = TAG[INTEGER.type]

    def __repr__(self):
        return f"INTEGER(value={self.value}, type={INTEGER.type}, length={self.length})"

    def der(self):
        """Returns <self> encoded in DER as a string.
        """
        return f"{self.tag} {self.length} {INTEGER.der_integer(self.value)}"


class SEQUENCE(ASN1_primitive):
    """Represents basic type of ASN_1: SEQUENCE.

    Attributes:
        type (str): A type of an object; class variable.
        length (int): An amount of bytes which is needed to encode
                        <object>'s value in DER.
        value (int): A value of sequence.
    """
    type = "SEQUENCE"

    def __init__(self, *args, type=None, length = None):
        """Instantiates an object of class <SEQUENCE>.

        Args:
            args (list): A list of objects of class <INTEGER>.
        """
        super().__init__(args)
        self.tag = TAG[SEQUENCE.type]

    def __repr__(self):
        formatted = ""
        for structure in self.value:
            formatted += "\n\t" + str(structure) + ","
        return f"SEQUENCE({formatted} \n type={SEQUENCE.type}, length={self.length})"

    def der(self):
        """Returns <self> encoded in DER as a string.
        """
        der_value = ""
        for field in self.value:
            der_value += field.der() + " "
        return f"{self.tag} {self.length} {der_value[:-1:]}"
