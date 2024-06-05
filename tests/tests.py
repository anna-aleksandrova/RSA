import sys
sys.path.insert(0, r'C:\Users\Admin\Desktop\rsa_keys\src')
import asn_1 # type: ignore
import rsa # type: ignore

def test_binary():
    """Tests function <binary> from module <asn_1>.
    
    Raises:
        AssertionError: If the function does not work correctly.
    """
    assert asn_1.binary(255) == "11111111"
    assert asn_1.binary(5) == "101"

def test_is_binary():
    """Tests function <is_binary> from module <asn_1>.
    
    Raises:
        AssertionError: If the function does not work correctly.
    """
    assert asn_1.is_binary(100011100010)
    assert asn_1.is_binary("00000000")
    try:
        asn_1.is_binary([])
    except ValueError:
        pass

def test_binary_extended():
    """Tests function <binary_extended> from from module <asn_1>.

    Raises:
        AssertionError: If the function does not work correctly.
    """
    assert asn_1.binary_extended(0) == "000000"
    assert asn_1.binary_extended(1) == "000001"
    assert asn_1.binary_extended(63) == "111111"
    try:
        asn_1.binary_extended(64)
    except ValueError:
        pass

def test_hex():
    """Tests function <hex> from module <asn_1>.
    
    Raises:
        AssertionError: If the function does not work correctly.
    """
    n = 1011010101
    assert asn_1.hex(n) == "2D5"

def test_hex_binary():
    """Tests function <hex_binary> from module <asn_1>.
    
    Raises:
        AssertionError: If the function does not work correctly.
    """
    n = "1FA"
    assert asn_1.hex(n) == "000111111010"

def test__decode():
    """Tests function <_decode> from module <asn_1>.

    Raises:
        AssertionError: If the function does not work correctly.
    """
    assert asn_1._decode('AgQA') == "02 04 00"
    assert asn_1.decode('b3Bl') == "6F 70 65"

def test_decode():
    """Tests function <decode> from module <asn_1>.

    Raises:
        AssertionError: If the function does not work correctly.
    """
    integer = asn_1.INTEGER(2**23)
    assert asn_1.decode(integer.base64()) == integer.der()
    integer = asn_1.INTEGER(128)
    assert asn_1.decode(integer.base64()) == integer.der()
    sequence = asn_1.SEQUENCE(asn_1.INTEGER(127), asn_1.INTEGER(255))
    assert asn_1.decode(sequence.base64()) == sequence.der()

def test_analyze():
    """Tests function <analyze> from module <asn_1>.

    Raises:
        AssertionError: If the function does not work correctly.
    """
    integer = asn_1.INTEGER(255)
    assert str(integer) == str(asn_1.analyze(integer.base64()))
    sequence = asn_1.SEQUENCE(asn_1.INTEGER(255), asn_1.INTEGER(255))
    assert str(sequence) == str(asn_1.analyze(sequence.base64()))
    sequence = asn_1.SEQUENCE(asn_1.INTEGER(255), asn_1.INTEGER(255), asn_1.INTEGER(256))
    assert str(sequence) == str(asn_1.analyze(sequence.base64()))
    sequence = asn_1.SEQUENCE(asn_1.INTEGER(127), asn_1.INTEGER(256), asn_1.SEQUENCE(asn_1.INTEGER(127), asn_1.INTEGER(255)), asn_1.SEQUENCE(asn_1.INTEGER(154)))
    assert str(sequence) == str(asn_1.analyze(sequence.base64()))

def test_der_integer():
    """Tests class method <der_integer> from class <ASN1_primitive> from module <asn_1>.
    
    Raises:
        AssertionError: If the function does not work correctly.
    """
    assert asn_1.ASN1_primitive.der_integer(50) == "32"
    assert asn_1.ASN1_primitive.der_integer(255) == "00 FF"
    assert asn_1.ASN1_primitive.der_integer(0) == "00"

def test_decimal():
    """Tests function <decimal> from module <asn_1>.
    
    Raises:
        AssertionError: If the function does not work correctly.
    """
    assert asn_1.decimal("11111111") == 255
    assert asn_1.decimal("00000000") == 0


def test_base64():
    """Tests function(class method) <base64> from class <ASN1_primitive> from module <asn_1>.

    Raises:
        AssertionError: If the function does not work correctly.
    """
    integer1 = asn_1.INTEGER(127)
    assert integer1.base64() == "AgF/"
    integer2 = asn_1.INTEGER(2**23)
    assert integer2.base64() == "AgQAgAAA"
    integer3 = asn_1.INTEGER(128)
    assert integer3.base64() == "AgIAgA=="
    integer4 = asn_1.INTEGER(2**15)
    assert integer4.base64() == "AgMAgAA="
    integer_1 = asn_1.INTEGER(127)
    integer_2 = asn_1.INTEGER(255)
    sequence = asn_1.SEQUENCE(integer_1, integer_2)
    assert sequence.base64() == "MAcCAX8CAgD/"

def test_generate():
    """Tests function (class method) <generate> from module <rsa>.

    Raises:
        AssertionError: If the function does not work correctly.
    """
    # print(rsa.Prime.generate(128))

def test_gcd():
    """Tests function <gcd> from module <rsa>.

    Raises:
        AssertionError: If the function does not work correctly.
    """
    assert rsa.gcd(1, 1) == 1
    assert rsa.gcd(2, 3) == 1
    assert rsa.gcd(15, 5) == 5
    assert rsa.gcd(5, 7) == 1

def test_gcd_extended():
    """Tests function <gcd_extended> from module <rsa>.

    Raises:
        AssertionError: If the function does not work correctly.
    """
    assert rsa.gcd_extended(0, 7) == (0, 1, 7)
    assert rsa.gcd_extended(100, 20) == (0, 1, 20)
    assert rsa.gcd_extended(20, 100) == (1, 0, 20)

def test_miller_rabin():
    """Tests function <miller_rabin> from module <rsa>.

    Raises:
        AssertionError: If the function does not work correctly.
    """
    assert rsa.miller_rabin(2) is True
    assert rsa.miller_rabin(51) is False
    assert rsa.miller_rabin(31) is True
    assert rsa.miller_rabin(20) is False
    assert rsa.miller_rabin(67280421310721) is True

def test_inverse():
    """Tests function (class method) <inverse> from class <Prime> from module <rsa>.

    Raises:
        AssertionError: If the function does not work correctly.
    """
    assert rsa.inverse(157, 2668) == 17

def test_rsa():
    """Tests whether writing a key into a file and reading it
        were implemented correctly.
    
    Raises:
        AssertionError: If the mechamism doesn't work correctly.
    """
    for i in range(40):
        print("\n------------------------NEW KEYPAIR------------------------")
        keypair = rsa.Keypair(256)
        # print(str(keypair._private.as_asn1()))
        keypair._private.write_into(r"C:\Users\Admin\Desktop\rsa_keys\src\private.txt")
        print(str(rsa.PrivateKey.read_from(r"C:\Users\Admin\Desktop\rsa_keys\src\private.txt")))
        assert str(keypair._private.as_asn1()) == str(rsa.PrivateKey.read_from(r"C:\Users\Admin\Desktop\rsa_keys\src\private.txt"))

        # print(str(keypair._public.as_asn1()))
        keypair._public.write_into(r"C:\Users\Admin\Desktop\rsa_keys\src\public.txt")
        print(str(rsa.PublicKey.read_from(r"C:\Users\Admin\Desktop\rsa_keys\src\public.txt")))
        assert str(keypair._public.as_asn1()).strip() == str(rsa.PublicKey.read_from(r"C:\Users\Admin\Desktop\rsa_keys\src\public.txt")).strip()

if __name__ == '__main__':
    test_der_integer()
    test_hex()
    test_binary()
    test_is_binary()
    test_base64()
    test_decimal()
    test_binary_extended()
    test_decode()
    test_analyze()
    test_generate()
    test_gcd()
    test_miller_rabin()
    test_gcd_extended()
    test_inverse()
    test_rsa()
    print("\nThe tests passed successfully.")
