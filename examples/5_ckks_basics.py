from seal import *
import numpy as np
import time
import sys

def print_vector(vector):
    print('[ ', end='')
    for i in range(0, 8):
        print(vector[i], end=', ')
    print('... ]')


def example_ckks_basics():
    parms = EncryptionParameters (scheme_type.ckks)
    poly_modulus_degree = 8192
    parms.set_poly_modulus_degree(poly_modulus_degree)
    parms.set_coeff_modulus(CoeffModulus.Create(poly_modulus_degree, [60, 40, 40, 60]))
    scale = pow(2.0, 40)
    context = SEALContext(parms)
    
    keygen = KeyGenerator(context)
    secret_key = keygen.secret_key()
    public_key = keygen.create_public_key()
    relin_keys = keygen.create_relin_keys()

    encryptor = Encryptor(context, public_key)
    evaluator = Evaluator(context)
    decryptor = Decryptor(context, secret_key)
    
    # CKKS Encoder
    ckks_encoder = CKKSEncoder(context)
    slot_count = ckks_encoder.slot_count()
    
    input_matrix = [0] * slot_count
    curr_point = 0
    step_size = 1.0 / (slot_count - 1)
    for i in range(slot_count):
        input_matrix.append(curr_point)
        curr_point += step_size

    plain_coeffVec = ckks_encoder.encode([3.141, 2, 3, 4, 4], scale)
    plain_coeff3 = ckks_encoder.encode(3.141, scale)
    plain_coeff1 = ckks_encoder.encode(0.4, scale)
    plain_coeff0 = ckks_encoder.encode(1.0, scale)
    plain_coeff8 = ckks_encoder.encode(0.125, scale)
    
    ### Encryption
    start = time.time()

    x3_encrypted = encryptor.encrypt(plain_coeff3)
    
    done = time.time()
    elapsed = done - start
    print(elapsed)
    x1_encrypted = encryptor.encrypt(plain_coeff1)
    x0_encrypted = encryptor.encrypt(plain_coeff0)
    x8_encrypted = encryptor.encrypt(plain_coeff8)
    vector_encrypted = encryptor.encrypt(plain_coeffVec)
    
    ### Addition
    print("Compute PI + 0.4 + 1.\n")
    encrypted_result = evaluator.add(x3_encrypted, x1_encrypted)
    encrypted_result = evaluator.add(x0_encrypted, encrypted_result)
    print(sys.getsizeof(encrypted_result))
    
    
    ### Multiplication
    #encrypted_result = evaluator.multiply_plain(encrypted_result, plain_coeff8)

    print(sys.getsizeof(encrypted_result))
    vec_result = evaluator.add(vector_encrypted, vector_encrypted)
    
    print("Expected Result: 4.541\n")
    ### Decryption
    start = time.time()
    
    decrypted_result = decryptor.decrypt(encrypted_result)
    done = time.time()
    elapsed = done - start
    print(elapsed)
    input_result = ckks_encoder.decode(decrypted_result)
    
    print_vector(input_result)
    print('Object Size Comparison: ')
    print(sys.getsizeof(x3_encrypted))
    print(sys.getsizeof(3.141))
    
    ### Vector
    print("Vector size: " + str(sys.getsizeof(vec_result)))
    print("Expected Result: [6.282, 4, 6, 8, 8]\n")
    
    decrypted_result = decryptor.decrypt(vec_result)
    input_result = ckks_encoder.decode(decrypted_result)
    
    print_vector(input_result)


if __name__ == "__main__":
    example_ckks_basics()
