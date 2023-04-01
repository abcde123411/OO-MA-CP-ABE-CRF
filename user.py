# User type
class User(object):

    def __init__(self):
        self.gid = 'Alex'
        self.user_attributes = []

    def __str__(self):
        return 'User [%s] with attributes %s created successfully!' % (self.gid, self.user_attributes)
