import sys
import paths
sys.path.insert(0, paths.src)
import asn_1 # type: ignore
import rsa # type: ignore

def read_public(filename):
    print("\n--------------------Your public key: --------------------\n")
    print(rsa.PublicKey.read_from(filename))

def read_private(filename):
    print("\n--------------------Your identification: --------------------\n")
    print(rsa.PrivateKey.read_from(filename))

if __name__ == "__main__":

    while True:
        choice = input("To generate new keypair or read a key from a file? [g/r]: ")
        if choice != "g" and choice != "r":
            print("Please, choose from two options that are given.")
        else:
            break

    if choice == "g":
        public = input("File to save public key in: ")
        private = input("File to save private key in: ")
        bits = int(input("Bits (type of the key): "))
        keypair = rsa.Keypair(bits)
        keypair.write_into(public, private)     
    elif choice == "r":
        while True:
            choice = input("To read public, private, both? [pub/priv/b]: ")
            if choice != "pub" and choice != "priv" and choice != "b":
                print("Please, choose from three options that are given.")
            else:
                break
        if choice == "pub":
            public = input("File to read public key from: ")
            read_public(public)
        elif choice == "priv":
            private = input("File to read private key from: ")
            read_private(private)
        elif choice == "b":
            public = input("File to read public key from: ")
            private = input("File to read private key from: ")
            read_public(public)
            read_private(private)
    else:
        pass