import os
import pickle
import string
from tqdm import tqdm

from gmssl import sm9
import SM9_Locally_Varifiable.setup_key as sk_new
import SM9_Locally_Varifiable.message_sign_and_verify as msav
import SM9_Locally_Varifiable.message_aggregate_sign_and_verify as masav
import SM9_Locally_Varifiable.message_aggregate_sign_and_verify_locally as masavl
from util.util import get_object_size

SUCCESS = True


def test(num):
    import time

    message = 'abc'
    messages1 = list(string.ascii_lowercase)
    messages2 = list(string.ascii_lowercase)
    messages3 = list(string.ascii_lowercase)
    cartesian_product = [item1 + item2 for item1 in messages1 for item2 in messages2]
    cartesian_product = [item1 + item2 for item1 in cartesian_product for item2 in messages3][:num]

    idA = 'a'
    master_public, master_secret = sm9.setup('sign')
    Da = sm9.private_key_extract('sign', master_public, master_secret, idA)

    # file_path = "../pickle_signature/" + str(num)
    # directory = os.path.dirname(file_path)
    # if not os.path.exists(directory):
    #     os.makedirs(directory)

    # print("\n\n\n\n\n-------------------------------国密SM9签名验签----------------------------------")
    # signature = sm9.sign(master_public, Da, message)
    #
    # # memory_usage = asizeof.asizeof(signature)
    # memory_usage = get_object_size(signature) - get_object_size(())
    #
    # for _ in range(num):
    #     with open('../pickle_signature/' + str(num) + '/sm9.pkl', 'ab') as file:
    #         pickle.dump(signature, file)
    #
    # print(f"国密SM9签名验签算法，生成{num}条消息的签名使用的内存：{memory_usage * num} 字节")

    # start_time = time.time()
    # for _ in tqdm(range(num), desc="Processing"):
    #     result = sm9.verify(master_public, idA, message, signature)
    # end_time = time.time()
    #
    # execution_time_ms = (end_time - start_time) * 1000
    # print(f"签名验证结果:{result}")
    # print(f"国密SM9签名验签算法，单独验证{num}条签名执行时间: {execution_time_ms:.2f} 毫秒")

    # master_public, master_secret = sk_new.setup('sign')
    # Da = sk_new.private_key_extract('sign', master_public, master_secret, idA)

    # print("--------------------------------修改后SM9签名验签-----------------------------------")
    # signature = msav.sign(master_public, Da, message)
    #
    # # memory_usage = asizeof.asizeof(signature)
    # memory_usage = get_object_size(signature) - get_object_size(())
    #
    # for _ in tqdm(range(num), desc="Processing"):
    #     with open('../pickle_signature/' + str(num) + '/sm9_new.pkl', 'ab') as file:
    #         pickle.dump(signature, file)
    #
    # print(f"SM9签名验签算法，生成{num}条消息的签名使用的内存：{memory_usage * num} 字节")

    # start_time = time.time()
    # for _ in tqdm(range(num), desc="Processing"):
    #     result = msav.verify(master_public, idA, message, signature)
    # end_time = time.time()
    #
    # execution_time_ms = (end_time - start_time) * 1000
    #
    # print(f"签名验证结果:{result}")
    # print(f"SM9签名验签算法,单独验证{num}条签名执行时间: {execution_time_ms:.2f} 毫秒")

    print("-------------------------------SM9聚合签名验签---------------------------------")
    start_time = time.time()
    signature = masav.sign_aggregate(master_public, Da, cartesian_product)
    end_time = time.time()
    execution_time_ms = (end_time - start_time) * 1000
    print(f"SM9聚合签名验签算法，生成{num}条消息的签名执行时间: {execution_time_ms:.2f} 毫秒")

    # memory_usage = asizeof.asizeof(signature)
    # memory_usage = get_object_size(signature)
    #
    # with open('../pickle_signature/' + str(num) + '/sm9_sign_aggregate.pkl', 'wb') as file:
    #     pickle.dump(signature, file)
    #
    # print(f"SM9聚合签名验签算法，生成{num}条消息的签名使用的内存：{memory_usage} 字节")

    start_time = time.time()
    result = masav.verify_aggregate(master_public, idA, cartesian_product, signature)
    end_time = time.time()

    execution_time_ms = (end_time - start_time) * 1000
    print(f"签名验证结果:{result}")
    print(f"修改后SM9聚合签名验签算法，验证{num}条签名执行时间: {execution_time_ms:.2f} 毫秒")

    print("----------------------------修改后SM9聚合签名局部可验证算法----------------------------")
    start_time = time.time()
    signature = masavl.sign_aggregate_locally(master_public, Da, cartesian_product, 0)
    end_time = time.time()
    execution_time_ms = (end_time - start_time) * 1000
    print(
        f"SM9聚合签名局部可验证算法，生成{num}条消息的签名，并针对某条消息生成提示信息执行时间: {execution_time_ms:.2f} 毫秒")

    # memory_usage = asizeof.asizeof(signature)
    # memory_usage = get_object_size(signature)
    #
    # with open('../pickle_signature/' + str(num) + '/sign_aggregate_locally.pkl', 'wb') as file:
    #     pickle.dump(signature, file)
    #
    # print(f"SM9聚合签名局部可验证算法，生成{num}条消息的签名使用的内存：{memory_usage} 字节")

    start_time = time.time()
    result = masavl.verify_aggregate_locally(master_public, idA, cartesian_product[0], signature)
    end_time = time.time()

    execution_time_ms = (end_time - start_time) * 1000
    print(f"签名验证结果:{result}")
    print(f"修改后SM9聚合签名局部可验证算法，选择性验证1条签名执行时间: {execution_time_ms:.2f} 毫秒")
    print("\n\n\n")
    pass


if __name__ == '__main__':
    test(100)
    test(200)
    test(300)
    test(400)
    test(500)
    test(600)

    pass
