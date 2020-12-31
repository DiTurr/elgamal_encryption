"""
ElGamal encryption
"""


class ElGamal:
    def __init__(self, prime, alfa, d, type="ElGamal"): # NOQA (due to type input and self.type shadow name)
        """
        
        """
        self.privat_key = d
        self.type = type
        self.public_key = {"p": prime,
                           "alfa": alfa,
                           "beta": self.modular_exponentation(alfa, d, prime)}

    def enconder(self, m, a):
        """
        
        """
        c1 = self.modular_exponentation(self.public_key["alfa"], a, self.public_key["p"])
        if self.type == "ElGamal":
            c2 = (self.modular_exponentation(self.public_key["beta"], a, self.public_key["p"]) * m) % \
                 self.public_key["p"]
        elif self.type == "ElGamalVariant":
            c2 = ((self.modular_exponentation(self.public_key["beta"], a, self.public_key["p"]) *
                   self.modular_exponentation(self.public_key["alfa"], a, self.public_key["p"])) * m) % \
                 self.public_key["p"]
        else:
            raise ValueError("[ERROR] Type of ElGamal not supported !")
        return c1, c2

    def decoder(self, c1, c2):
        """
        
        """
        if self.type == "ElGamal":
            temp = self.modular_exponentation(c1, -self.privat_key, self.public_key["p"])
            result = (c2 * temp) % self.public_key["p"]
        elif self.type == "ElGamalVariant":
            temp = self.modular_exponentation(c1, -self.privat_key, self.public_key["p"])
            temp = temp * self.modular_exponentation(c1, -1, self.public_key["p"])
            result = (c2 * temp) % self.public_key["p"]
        else:
            raise ValueError("[ERROR] Type of ElGamal not supported !")

        return result

    def public_key(self):
        """
        
        """
        return self.public_key

    @staticmethod
    def modular_exponentation(x, e, m):
        """
        
        """
        return pow(x, e, m)


if __name__ == '__main__':
    # parameters / inputs
    prime_usr = 15485863
    alfa_usr = 7
    d_usr = 21702
    msg_orig = 128688
    a_usr = 480
    # prime_usr = 17
    # alfa_usr = 3
    # d_usr = 6
    # msg_orig = 16
    # a_usr = 5

    # define class
    cripto = ElGamal(prime_usr, alfa_usr, d_usr, type="ElGamalVariant")
    print(cripto.public_key)
    c1_send, c2_send = cripto.enconder(msg_orig, a_usr)
    print(c1_send, c2_send)
    msg_rcv = cripto.decoder(c1_send, c2_send)
    print(msg_rcv)
    assert msg_rcv == msg_orig
