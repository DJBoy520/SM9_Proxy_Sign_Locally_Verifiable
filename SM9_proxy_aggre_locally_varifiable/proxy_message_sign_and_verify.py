FAILURE = False
SUCCESS = True


def proxy_public_key_extract(scheme, master_public, identity_original, identity_proxy,
                             authorization_information):
    import SM9_Proxy_Sign.proxy_message_sign_and_verify

    return SM9_Proxy_Sign.proxy_message_sign_and_verify.proxy_public_key_extract(scheme, master_public,
                                                                                 identity_original, identity_proxy,
                                                                                 authorization_information)
# scheme = 'sign'
def sign(master_public, Da, msg):
    import SM9_Proxy_Sign.proxy_message_sign_and_verify
    return SM9_Proxy_Sign.proxy_message_sign_and_verify.sign(master_public, Da, msg)


def verify(master_public, msg, signature, identity_original, identity_proxy, authorization_information):
    import SM9_Proxy_Sign.proxy_message_sign_and_verify
    return SM9_Proxy_Sign.proxy_message_sign_and_verify.verify(master_public, msg, signature, identity_original,
                                                               identity_proxy, authorization_information)


if __name__ == '__main__':
    pass
