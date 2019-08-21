# https://www.pycryptodome.org/en/latest/src/examples.html

"""
Обеспечить работу в обоих режимах: скриптовом (1 команда) и консольном (полноценное взаимодействие с пользователем)
"""

from Crypto.Cipher import AES
from Crypto.Hash import SHA3_256
import os
import sys


def pass_read(msg=""):
    os.system('echo off')
    os.system(f'powershell -Command $pword = read-host "{msg}" -AsSecureString ; $BSTR=[System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($pword) ; [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR) > .tmp.txt')
    f = open('.tmp.txt', 'r')
    password = f.read()
    f.close()
    os.remove('./.tmp.txt')
    os.system('echo on')
    return password


def sha3_256_key(password):
    return SHA3_256.new(password.encode('ASCII')).digest()


def encrypt_file(path_to_file, key, remove_file=True):
    error = False

    file_name_in = os.path.basename(path_to_file)
    file_name_out = file_name_in + '.encrypted'
    path_to_file = os.path.dirname(path_to_file)
    prev_dir = os.path.abspath(os.curdir)
    os.chdir(path_to_file)

    file_in = open(file_name_in, "rb")
    try:
        data = file_in.read()
        cipher = AES.new(key, AES.MODE_EAX)
        cipher_text, tag = cipher.encrypt_and_digest(data)
    except:
        error = True

    file_in.close()
    if not error:
        file_out = open(file_name_out, "wb")
        [file_out.write(x) for x in (cipher.nonce, tag, cipher_text)]
        file_out.close()

    if not error and remove_file:
        os.remove(file_name_in)

    os.chdir(prev_dir)

    return not error


def decrypt_file(path_to_file, key, remove_file=True):
    error = False
    another_extension = True

    file_name_in = os.path.basename(path_to_file)
    file_name_out = file_name_in
    if '.encrypted' in file_name_out:
        another_extension = False
        file_name_out = file_name_out[:-len('.encrypted')]
    path_to_file = os.path.dirname(path_to_file)
    prev_dir = os.path.abspath(os.curdir)
    os.chdir(path_to_file)

    file_in = open(file_name_in, "rb")
    try:
        nonce, tag, cipher_text = [file_in.read(x) for x in (16, 16, -1)]
        cipher = AES.new(key, AES.MODE_EAX, nonce)
        data = cipher.decrypt_and_verify(cipher_text, tag)
    except:
        error = True

    file_in.close()
    if not error:
        file_out = open(file_name_out, "wb")
        file_out.write(data)
        file_out.close()

    if not error and remove_file and not another_extension:
        os.remove(file_name_in)

    os.chdir(prev_dir)

    return not error


# ----- MAIN PROGRAMM -----
if __name__ == '__main__':
    msg_done_en = 'File was successfully encrypted'
    msg_done_de = 'File was successfully decrypted'
    msg_err_en = 'Encryption wasn\'t finished. Wrong password or file is corrupted'
    msg_err_de = 'Decryption wasn\'t finished. Wrong password or file is corrupted'
    msg_err_argv = 'Wrong arguments. Use \'-h\' for help'
    msg_err_path = 'Wrong path'
    msg_help = ('Use: "crypto.py <path> <flags>"\n'
                '<path> - Path to file you want to (de-)encrypt\n'
                'If path contain spaces use ""'
                '<flags>: "-e|-d [-s]"\n'
                '  \'-e\' - Encrypt file\n'
                '  \'-d\' - Decrypt file\n'
                '  \'-s\' - Do not remove source file after processing\n')

    if '-h' in sys.argv:
        print(msg_help)
        exit(0)

    if '-e' in sys.argv and '-d' in sys.argv:
        print(msg_err_argv)
        exit(1)

    if '-s' in sys.argv:
        remove = False
    else:
        remove = True

    if not (2 < len(sys.argv) < 5):
        print(msg_err_argv)
        exit(1)

    path = os.path.abspath(sys.argv[1])
    if not os.path.exists(path) or not os.path.isfile(path):
        print(msg_err_path)
        exit(1)

    password = pass_read("Enter password")

    if '-e' in sys.argv:
        result = encrypt_file(path, sha3_256_key(password), remove)
        if result:
            print(msg_done_en)
        else:
            print(msg_err_en)
    else:
        if '-d' in sys.argv:
            result = decrypt_file(path, sha3_256_key(password), remove)
            if result:
                print(msg_done_de)
            else:
                print(msg_err_de)
        else:
            print(msg_err_argv)
            exit(1)
