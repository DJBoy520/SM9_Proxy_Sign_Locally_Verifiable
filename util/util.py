import sys

from sympy import symbols, expand, nextprime
from math import ceil, floor, log
import binascii
from gmssl.sm3 import sm3_kdf, sm3_hash


def bitlen(n):
    return floor(log(n, 2) + 1)


def i2sp(m, l):
    format_m = ('%x' % m).zfill(l * 2).encode('utf-8')
    octets = [j for j in binascii.a2b_hex(format_m)]
    octets = octets[0:l]
    return ''.join(['%02x' % oc for oc in octets])


def fe2sp(fe):
    fe_str = ''.join(['%x' % c for c in fe.coeffs])
    if (len(fe_str) % 2) == 1:
        fe_str = '0' + fe_str
    return fe_str


def ec2sp(P):
    ec_str = ''.join([fe2sp(fe) for fe in P])
    return ec_str


def str2hexbytes(str_in):
    return [b for b in str_in.encode('utf-8')]


def h2rf(i, z, n):
    l = 8 * ceil((5 * bitlen(n)) / 32)
    msg = i2sp(i, 1).encode('utf-8')
    ha = sm3_kdf(msg + z, l)
    h = int(ha, 16)
    return (h % (n - 1)) + 1


def calculate_coefficient_from_constants(constants):
    x = symbols('x')
    result = 1

    for b in constants:
        result *= (x + b)

    expanded_result = expand(result)
    coefficients = expanded_result.as_coefficients_dict()

    return coefficients


def calculate_coefficient_with_modulus(constants, N):
    x = symbols('x')
    result = 1

    for b in constants:
        result *= (x + b)

    expanded_result = expand(result)
    coefficients = expanded_result.as_coefficients_dict()
    C = []

    for key in coefficients:
        coefficients[key] = coefficients[key] % N
        C.append(coefficients[key] % N)
    return C


def get_object_size(obj, seen=None):
    if seen is None:
        seen = set()
    obj_id = id(obj)

    if obj_id in seen:
        # 如果对象已经被处理过，不重复计算
        return 0

    seen.add(obj_id)
    size = sys.getsizeof(obj)

    if hasattr(obj, '__dict__'):
        size += get_object_size(obj.__dict__, seen)

    if isinstance(obj, (list, tuple, set, frozenset)):
        size += sum(get_object_size(item, seen) for item in obj)

    if isinstance(obj, dict):
        size += sum(get_object_size(key, seen) + get_object_size(value, seen) for key, value in obj.items())

    return size


if __name__ == '__main__':
    # # 示例用法
    N = 2 ** 256  # 替换为你希望的 x 值
    prime = nextprime(N)

    # constants = [5876578657657657657623452345, 23452345234524523461452345, 23452345134523451234523452345,
    #              234523452345256365679967823413441234,
    #              23452345234525636567996782341344123423452345256365679967823413441234234523452345256365679967823413441234234523452345256365679967823413441234,
    #              2345234523452563656799678234134412342345234523452563656799678234234523452345256365679967823413441234234523452345256365679967823413441234,
    #              23452345234525636567996782341344123423452346365679967823413441234234523452345256365679967823413441234234523452345256365679967823413441234234523452345256365679967823413441234]

    constants = [1, 2, 3]
    coefficients = calculate_coefficient_with_modulus(constants, prime)

    C = coefficients[::-1]
    print(coefficients)
    print(C)

    # print(get_object_size(()))
    # print(get_object_size(385649684165489465135196874489644321564231321))
