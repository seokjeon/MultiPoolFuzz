# Example of a Python script that crashes
# catch the exception to prevent the crash


class Crash(Exception):
    pass


def leaf(label, s, i):
    if i == len(s):
        return label
    return "NO MATCH"

def leaf_crash(s, i):
    raise Exception("💥 real_bad! reached")

def fail():
    return "NO MATCH"


# -------- just_good / just_soso --------
def j(s, i=0):
    if i < len(s) and s[i] == 'j':
        return u(s, i + 1)
    return fail()

def u(s, i):
    if i < len(s) and s[i] == 'u':
        return s1(s, i + 1)
    return fail()

def s1(s, i):
    if i < len(s) and s[i] == 's':
        return t(s, i + 1)
    return fail()

def t(s, i):
    if i < len(s) and s[i] == 't':
        return uscore_j(s, i + 1)
    return fail()

def uscore_j(s, i):
    if i < len(s) and s[i] == '_':
        if i + 1 < len(s) and s[i + 1] == 'g':
            return g1(s, i + 1)
        elif i + 1 < len(s) and s[i + 1] == 's':
            return s2(s, i + 1)
    return fail()

def g1(s, i):
    if i < len(s) and s[i] == 'g':
        return o1(s, i + 1)
    return fail()

def o1(s, i):
    if i < len(s) and s[i] == 'o':
        return o2(s, i + 1)
    return fail()

def o2(s, i):
    if i < len(s) and s[i] == 'o':
        return d1(s, i + 1)
    return fail()

def d1(s, i):
    if i < len(s) and s[i] == 'd':
        return leaf("just_good", s, i + 1)
    return fail()

def s2(s, i):
    if i < len(s) and s[i] == 's':
        return o3(s, i + 1)
    return fail()

def o3(s, i):
    if i < len(s) and s[i] == 'o':
        return s3(s, i + 1)
    return fail()

def s3(s, i):
    if i < len(s) and s[i] == 's':
        return o4(s, i + 1)
    return fail()

def o4(s, i):
    if i < len(s) and s[i] == 'o':
        return leaf("just_soso", s, i + 1)
    return fail()


# -------- real_good / real_bad! --------
def r(s, i=0):
    if i < len(s) and s[i] == 'r':
        return e(s, i + 1)
    return fail()

def e(s, i):
    if i < len(s) and s[i] == 'e':
        return a(s, i + 1)
    return fail()

def a(s, i):
    if i < len(s) and s[i] == 'a':
        return l(s, i + 1)
    return fail()

def l(s, i):
    if i < len(s) and s[i] == 'l':
        return uscore_r(s, i + 1)
    return fail()

def uscore_r(s, i):
    if i < len(s) and s[i] == '_':
        if i + 1 < len(s) and s[i + 1] == 'g':
            return g2(s, i + 1)
        elif i + 1 < len(s) and s[i + 1] == 'b':
            return b1(s, i + 1)
    return fail()

def g2(s, i):
    if i < len(s) and s[i] == 'g':
        return o5(s, i + 1)
    return fail()

def o5(s, i):
    if i < len(s) and s[i] == 'o':
        return o6(s, i + 1)
    return fail()

def o6(s, i):
    if i < len(s) and s[i] == 'o':
        return d2(s, i + 1)
    return fail()

def d2(s, i):
    if i < len(s) and s[i] == 'd':
        return leaf("real_good", s, i + 1)
    return fail()

def b1(s, i):
    if i < len(s) and s[i] == 'b':
        return a2(s, i + 1)
    return fail()

def a2(s, i):
    if i < len(s) and s[i] == 'a':
        return d3(s, i + 1)
    return fail()

def d3(s, i):
    if i < len(s) and s[i] == 'd':
        return ex(s, i + 1)
    return fail()

def ex(s, i):
    if i < len(s) and s[i] == '!':
        return leaf_crash(s, i + 1)  # 💥 여기서만 Exception 발생
    return fail()


# -------- Root --------
def branching_program(s: str) -> str:
    if not s:
        return "NO MATCH"
    if s[0] == 'j':
        return u(s, 1)
    elif s[0] == 'r':
        return e(s, 1)
    return fail()



