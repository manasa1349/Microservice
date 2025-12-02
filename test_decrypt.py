from app.crypto_utils import load_private_key, decrypt_seed

with open("encrypted_seed.txt") as f:
    encrypted_seed = f.read().strip()

private_key = load_private_key()
seed = decrypt_seed(encrypted_seed, private_key)

print("Decrypted seed:", seed)
print("Length:", len(seed))