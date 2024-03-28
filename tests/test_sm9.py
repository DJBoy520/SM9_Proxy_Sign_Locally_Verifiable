# import sys
# sys.path.append('../gmssl/')
from gmssl import sm9

if __name__ == '__main__':
    import time

    idA = 'a'
    idB = 'b'

    print("-----------------test sm9 sign and verify---------------")

    master_public, master_secret = sm9.setup('sign')

    start_time = time.time()
    for i in range(100):
        Da = sm9.private_key_extract('sign', master_public, master_secret, idA)
    end_time = time.time()
    execution_time_ms = (end_time - start_time) * 1000
    print(f"private_key_extract 执行时间: {execution_time_ms:.2f} 毫秒")

    message = 'abc'

    start_time_sign = time.time()
    for i in range(100):
        signature = sm9.sign(master_public, Da, message)
    end_time_sign = time.time()
    execution_time_ms = (end_time_sign - start_time_sign) * 1000
    print(f"sm9签名执行100时间: {execution_time_ms:.2f} 毫秒")

    start_time = time.time()
    for i in range(100):
        result = sm9.verify(master_public, idA, message, signature)
        end_time = time.time()

        execution_time_ms = (end_time - start_time) * 1000
        print(f"验证签名执行时间: {execution_time_ms:.2f} 毫秒")

        print(result)

        # print ("-----------------test key agreement---------------")
        #
        # master_public, master_secret = sm9.setup ('keyagreement')
        #
        # Da = sm9.private_key_extract ('keyagreement', master_public, master_secret, idA)
        # Db = sm9.private_key_extract ('keyagreement', master_public, master_secret, idB)
        #
        # xa, Ra = sm9.generate_ephemeral (master_public, idB)
        # xb, Rb = sm9.generate_ephemeral (master_public, idA)
        #
        # ska = sm9.generate_session_key (idA, idB, Ra, Rb, Da, xa, master_public, 'A', 128)
        # skb = sm9.generate_session_key (idA, idB, Ra, Rb, Db, xb, master_public, 'B', 128)
        #
        # assert (ska == skb)
        #
        # print ("\t\t\t success")
        #
        # print ("-----------------test encrypt and decrypt---------------")
        #
        # master_public, master_secret = sm9.setup ('encrypt')
        #
        # Da = sm9.private_key_extract ('encrypt', master_public, master_secret, idA)
        #
        # message = 'abc'
        # ct = sm9.kem_dem_enc (master_public, idA, message, 32)
        # pt = sm9.kem_dem_dec (master_public, idA, Da, ct, 32)
        #
        # assert (message == pt)
        #
        # print ("\t\t\t success")

        pass
