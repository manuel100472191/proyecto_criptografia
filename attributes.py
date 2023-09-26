class Attributes:
    @staticmethod
    def validate_user(phone_number: str, password: str, name: str, surname: str, email: str):
        try:
            int(phone_number)
        except ValueError:
            return False
        if len(phone_number) != 9:
            return False
        return True
