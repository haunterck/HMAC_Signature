import hmac
import hashlib

from typing import Any, Optional, Union

class HmacSignatureGenerator:

    ALGORITHMS_ACCEPTED = {
        "md5": hashlib.md5(),
        "sha256": hashlib.sha256(),
        "sha512": hashlib.sha512()
    }

    def __init__(
        self, key: str, message: Union[str, dict, list],
        algorithm: str = None
    ):
        """
        Setup the variable classes
        :param key: Key value to use a value that only the people that generate
        and validathe the signature to be created know it
        :param message: Is the message to be hashed according with the key and
        algorithm to be used
        :param algorithm: Value that indicates which algorihm must be used at
        the moment to generate a signature with HMAC. The options are the 
        values from ALGORITHMS_ACCEPTED constant
        """
        self.key = key
        if not isinstance(message, str):
            message = str(message)
        self.message = message
        if algorithm.lower() in self.ALGORITHMS_ACCEPTED:
            self.algorith = self.ALGORITHMS_ACCEPTED[algorithm]
        else: self.algorith = self.ALGORITHMS_ACCEPTED["sha256"]

    def get_signature(self):
        
        return hmac.new(
            key=self.key.encode('utf-8'),
            msg=self.message.encode('utf-8'),
            digestmod=hashlib.sha256
        ).hexdigest().upper()
    
if __name__ == "__main__":
    print("ENTROOOO")

    obj1 = HmacSignatureGenerator(
        key="qwerty",
        message={
            "id": 1,
            "amount": 500.56
        },
        algorithm="sha256"
    )
    sign1 = obj1.get_signature()
    print(f"Signature for obj1: {sign1}")

    obj2 = HmacSignatureGenerator(
        key="qwerty",
        message="Hola Álvaro",
        algorithm="sha256"
    )
    sign2 = obj2.get_signature()
    print(f"Signature for obj2: {sign2}")

    if sign1 == sign2:
        print("La data es íntegra")
    else:
        print("La data NO es íntegra")
