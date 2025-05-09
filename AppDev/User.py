# User class
class User:
    count_id = 0

    def __init__(self, first_name, last_name, gender, number, email, pswd, cfm_pswd):
        User.count_id += 1
        self.__user_id = User.count_id
        self.__first_name = first_name
        self.__last_name = last_name
        self.__gender = gender
        self.__number = number
        self.__email = email
        self.__pswd = pswd
        self.__cfm_pswd = cfm_pswd
        self.__is_staff = self.check_if_staff(email)

    def check_if_staff(self, email):
        return email.endswith('@cropzy.com')

    # accessor methods
    def get_user_id(self):
        return self.__user_id

    def get_first_name(self):
        return self.__first_name

    def get_last_name(self):
        return self.__last_name

    def get_gender(self):
        return self.__gender

    def get_number(self):
        return self.__number

    def get_email(self):
        return self.__email

    def get_pswd(self):
        return self.__pswd

    def get_cfm_pswd(self):
        return self.__cfm_pswd

    def get_is_staff(self):
        return self.__is_staff

    # mutator methods
    def set_user_id(self, user_id):
        self.__user_id = user_id

    def set_first_name(self, first_name):
        self.__first_name = first_name

    def set_last_name(self, last_name):
        self.__last_name = last_name

    def set_gender(self, gender):
        self.__gender = gender

    def set_number(self, number):
        self.__number = number

    def set_email(self, email):
        self.__email = email

    def set_pswd(self, pswd):
        self.__pswd = pswd

    def set_cfm_pswd(self, cfm_pswd):
        self.__cfm_pswd = cfm_pswd

    def set_is_staff(self, is_staff):
        self.__is_staff = is_staff
