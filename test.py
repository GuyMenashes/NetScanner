from scapy.all import *
class b:
    def __init__(self,a) -> None:
        self.a=a
    
    def p(self):
        print(self.a.name)

class a():
    def __init__(self):
        self.name='f'
        self.wee=b(self)

f=a()
f.wee.p()