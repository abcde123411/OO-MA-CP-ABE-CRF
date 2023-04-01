# Authority type
class Authority(object):

    def __init__(self, theta):
        self.theta = theta
        self.authority_attributes = []

    def __str__(self):
        return 'Authority [%s] with attributes %s created successfully!' % (self.theta, self.authority_attributes)
