from tqdm import tqdm

FAILURE = False
SUCCESS = True


def proxy_public_key_extract(scheme, master_public, identity_original, identity_proxy,
                             authorization_information):
    import SM9_Proxy_Sign.proxy_message_sign_and_verify

    return SM9_Proxy_Sign.proxy_message_sign_and_verify.proxy_public_key_extract(scheme, master_public,
                                                                                 identity_original, identity_proxy,
                                                                                 authorization_information)


# scheme = 'sign'
def proxy_sign(master_public, Da, msg):
    import SM9_Proxy_Sign.proxy_message_sign_and_verify
    return SM9_Proxy_Sign.proxy_message_sign_and_verify.sign(master_public, Da, msg)


def proxy_verify(master_public, msg, signature, identity_original, identity_proxy, authorization_information):
    import SM9_Proxy_Sign.proxy_message_sign_and_verify
    return SM9_Proxy_Sign.proxy_message_sign_and_verify.verify(master_public, msg, signature, identity_original,
                                                               identity_proxy, authorization_information)


if __name__ == '__main__':
    import time
    import SM9_proxy_aggre_locally_varifiable.setup_key as setup
    import SM9_proxy_aggre_locally_varifiable.proxy_authorization as proxy_auth

    num = 1

    scheme = 'sign'
    idA = 'a'
    idC = 'c'
    auth_info = "a->c"

    msg = "abc"

    print("-----------------test proxy sign and verify---------------")

    master_public, master_secret = setup.setup('sign')

    start_time = time.time()
    for i in tqdm(range(num), desc="generate proxy auth"):
        Da = setup.private_key_extract(scheme, master_public, master_secret, idA)
    end_time = time.time()
    execution_time_ms = (end_time - start_time) * 1000
    print(f"generate proxy auth 执行时间: {execution_time_ms:.2f} 毫秒")

    start_time = time.time()
    for i in tqdm(range(num), desc="proxy auth to"):
        signature_auth = proxy_auth.proxy_auth_to(master_public, Da, auth_info)
    end_time = time.time()
    execution_time_ms = (end_time - start_time) * 1000
    print(f"proxy auth to 执行时间: {execution_time_ms:.2f} 毫秒")

    start_time = time.time()
    for i in tqdm(range(num), desc="private_key_extract"):
        Dac = proxy_auth.proxy_private_key_extract(scheme, master_public, master_secret, signature_auth, idA,
                                                   idC, auth_info)
    end_time = time.time()
    execution_time_ms = (end_time - start_time) * 1000
    print(f"private_key_extract 执行时间: {execution_time_ms:.2f} 毫秒")

    start_time = time.time()
    for i in tqdm(range(num), desc="proxy sign"):
        signature_proxy_sign = proxy_sign(master_public, Dac, msg)
    end_time = time.time()
    execution_time_ms = (end_time - start_time) * 1000
    print(f"proxy sign 执行时间: {execution_time_ms:.2f} 毫秒")

    start_time = time.time()
    for i in tqdm(range(num), desc="proxy verify"):
        result = proxy_verify(master_public, msg, signature_proxy_sign, idA, idC, auth_info)
    end_time = time.time()
    execution_time_ms = (end_time - start_time) * 1000
    print(f"proxy verify 执行时间: {execution_time_ms:.2f} 毫秒")

    print(result)
    pass
