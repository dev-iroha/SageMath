from Crypto.Cipher import DES

# 주어진 힌트 (암호화된 'DreamHack_blocks')
hint = "83a20b27b32e301c7877cd72b56524f1"
hint_bytes = bytes.fromhex(hint)

# 목표 문자열 ('DreamHack_blocks')
target_msg = b'DreamHack_blocks'

# 브루트포스를 통해 키를 찾고 플래그 복호화
for i in range(256**4):
    random_part = i.to_bytes(4, byteorder='big')
    key = b'Dream_' + random_part + b'Hacker'
    
    key1 = key[:8]
    key2 = key[8:]
    
    cipher1 = DES.new(key1, DES.MODE_ECB)
    cipher2 = DES.new(key2, DES.MODE_ECB)
    
    encrypt = lambda x: cipher2.encrypt(cipher1.encrypt(x))
    
    # 올바른 키 찾기
    if encrypt(target_msg) == hint_bytes:
        print(f"Found the key: {key.hex()}")
        
        decrypt = lambda x: cipher1.decrypt(cipher2.decrypt(x))
        
        # 주어진 암호화된 메시지
        with open("encrypted_flag.txt", "rb") as f:  # 여기에 암호화된 플래그가 있어야 함
            encrypted_flag = f.read().strip()
        
        # 암호화된 메시지를 복호화
        flag = decrypt(encrypted_flag)
        
        # DH{...} 형식의 플래그가 있는지 확인
        if flag.startswith(b'DH{'):
            print(f"Decrypted flag: {flag.decode()}")
        else:
            print("Flag format not recognized")
        break
