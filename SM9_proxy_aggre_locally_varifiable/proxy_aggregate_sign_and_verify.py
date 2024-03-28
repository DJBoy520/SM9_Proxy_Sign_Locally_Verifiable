import string

from gmssl.sm3 import sm3_hash
from random import SystemRandom
import gmssl.optimized_curve as ec
from gmssl.sm9 import fe2sp
from util.util import str2hexbytes, h2rf
import gmssl.optimized_field_elements as fq
from tqdm import tqdm

FAILURE = False
SUCCESS = True


def sign_aggregate(master_public, Da, msgs):
    import SM9_Locally_Varifiable.message_aggregate_sign_and_verify
    return SM9_Locally_Varifiable.message_aggregate_sign_and_verify.sign_aggregate(master_public, Da, msgs)


def verify_aggregate(master_public, identity, msgs, signature):
    import SM9_Locally_Varifiable.message_aggregate_sign_and_verify
    return SM9_Locally_Varifiable.message_aggregate_sign_and_verify.verify_aggregate(master_public, identity, msgs,
                                                                                     signature)


if __name__ == '__main__':

    pass
