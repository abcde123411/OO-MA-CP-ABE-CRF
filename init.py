from random import randint, sample
from authority import Authority
from user import User
from ABE import ABE


# initial type
class init(object):

    def __init__(self, attributes_num, authority_num=1, user_num=1, security_parameter='SS512'):
        self.attributes_num = attributes_num
        self.authority_num = authority_num
        self.user_num = user_num
        self.security_parameter = security_parameter
        self.attributes_set = [str(attr) for attr in range(self.attributes_num)]

    def createABE(self):
        """ create the ABE """
        return ABE(self.security_parameter)

    def createAuthority(self):
        """ create the authority """
        authority_list = [Authority(theta) for theta in range(self.authority_num)]

        # assign attributes to each authority
        for attr in self.attributes_set:
            theta = randint(0, self.authority_num - 1)
            authority_list[theta].authority_attributes.append(attr)

        # view the attributes of each authority
        [print(authority_list[theta]) for theta in range(self.authority_num)]

        return authority_list

    def createUser(self):
        """ create the user """
        user = User()

        user_attributes_num = randint(1, self.attributes_num)
        user.user_attributes = sample(self.attributes_set, user_attributes_num)

        # view the attributes of each user
        print(user)

        return user
