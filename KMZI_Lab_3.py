import subprocess
from math import log
from time import time
from sympy import mod_inverse


class Cryptor:
    def __init__(self, exe_path):
        self.exe_path = exe_path
        self.process = None
        self.stdin = None
        self.stdout = None
        self.interactions = 0

    def run(self):
        self.process = subprocess.Popen(args=self.exe_path, stdout=subprocess.PIPE, stdin=subprocess.PIPE)
        self.stdout = self.process.stdout
        self.stdin = self.process.stdin

    def interact(self, c):
        self.interactions += 1
        line = '{0:x}\r\n'.format(c).encode()
        self.stdin.write(line)
        self.stdin.flush()
        time = int(self.stdout.readline())
        message = int(self.stdout.readline().strip(), 16)
        return message, time

    def close(self):
        if self.process:
            self.process.kill()



def attack(g, l, s, R, j, delta, cryptor, n):
    print('Check {} byte '.format(j + 1))
    t_1_list, t_2_list = [], []
    g_ = g | (1 << (511 - j))
    for i in range(0, l):
        u_g, u_g_ = ((g + i) * pow(R, -1, n)) % n, ((g_ + i) * pow(R, -1, n)) % n
        t_1 = t_2 = 0
        for i in range(0, s):
            message, time = cryptor.interact(u_g)
            t_1 += time
            message, time = cryptor.interact(u_g_)
            t_2 += time
        t_1_list.append(t_1 / s)
        t_2_list.append(t_2 / s)
    T_g, T_g_  = sum(t_1_list), sum(t_2_list)
    new_delta = abs(T_g - T_g_)
    print('delta =', new_delta ,end=', ')
    if new_delta < delta:
        print('Put 1 on {} byte'.format(j + 1))
        return g_, new_delta
    else:
        print('Put 0 on {} byte'.format(j + 1))
        return g, new_delta



def execute_the_program(n, e, l, s, delta):
    R = int(2 ** ((log(n, 2) // 2) + 1))
    cryptor = Cryptor('v7\cryptor_v7.exe')
    cryptor.run()
    min_time = 10 ** 5
    for number in range(4, 8):
        g = number << 509
        message, time = cryptor.interact(g)
        if time < min_time:
            min_time, min_time_g = time, g
    g = min_time_g
    print('g =', g)
    for i in range(3, 512):
        g, delta_ = attack(g, l, s, R, i, delta, cryptor, n)
    cryptor.close()
    q = g
    p = n // q
    print('p = {}, q = {}, n = {}, p * q = {}'.format(p, q, n, p * q))

    res = mod_inverse(e, (p - 1) * (q - 1))
    return res


if __name__ == '__main__':
    n = 0xb398b5aa46a6f6750732ceb5b5a22b63adc56a6e252a608baa9d2b519e1c7d8545ab48991e20c5208461272b2dedbae296a462863aaf9ebecf9c33c09c70a674a2869d0f6fc7d0fb94e078341d3a8e60df3260ffa7f8bd0fb9a409dcf7bc91fe38f07902f79067e43b87345ac9f1acd7632028f6f191d32eecf76c573814668d
    e = 0x010001
    l = 5
    s = 1
    delta = 500000
    timer = time()
    d = execute_the_program(n, e, l, s, delta)
    print('d =', d)
    timer = time() - timer
    message = 24141242141241
    cipher = pow(message, e, n)
    decipher = pow(cipher, d, n)
    if message == decipher:
        print('Success attack,time: {}'.format(timer))
    else:
        print('Failed attack')
