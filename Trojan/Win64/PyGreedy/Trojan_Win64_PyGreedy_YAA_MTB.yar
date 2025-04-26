
rule Trojan_Win64_PyGreedy_YAA_MTB{
	meta:
		description = "Trojan:Win64/PyGreedy.YAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,12 00 12 00 09 00 00 "
		
	strings :
		$a_01_0 = {49 66 20 79 6f 75 20 61 72 65 20 6c 6f 6f 6b 69 6e 67 20 61 74 20 74 68 69 73 20 69 73 20 62 65 63 61 75 73 65 20 79 6f 75 20 61 72 65 20 74 72 79 69 6e 67 20 74 6f 20 75 6e 64 65 72 73 74 61 6e 64 20 77 68 61 74 20 74 68 69 73 20 73 61 6d 70 6c 65 20 64 6f 65 73 2e 20 54 68 69 73 20 69 73 20 6a 75 73 74 20 61 6e 20 65 78 70 65 72 69 6d 65 6e 74 61 6c 20 74 6f 6f 6c } //10 If you are looking at this is because you are trying to understand what this sample does. This is just an experimental tool
		$a_01_1 = {43 72 79 70 74 6f 2e 43 69 70 68 65 72 2e 5f 45 4b 53 42 6c 6f 77 66 69 73 68 } //1 Crypto.Cipher._EKSBlowfish
		$a_01_2 = {62 43 72 79 70 74 6f 5c 43 69 70 68 65 72 5c 5f 72 61 77 5f 61 65 73 2e 70 79 64 } //1 bCrypto\Cipher\_raw_aes.pyd
		$a_01_3 = {50 59 49 4e 53 54 41 4c 4c 45 52 5f 53 54 52 49 43 54 5f 55 4e 50 41 43 4b 5f 4d 4f 44 45 } //1 PYINSTALLER_STRICT_UNPACK_MODE
		$a_01_4 = {65 6d 61 69 6c 2e 5f 65 6e 63 6f 64 65 64 5f 77 6f 72 64 73 } //1 email._encoded_words
		$a_01_5 = {65 6d 61 69 6c 2e 5f 68 65 61 64 65 72 5f 76 61 6c 75 65 5f 70 61 72 73 65 72 } //1 email._header_value_parser
		$a_01_6 = {65 6d 61 69 6c 2e 6d 65 73 73 61 67 65 } //1 email.message
		$a_01_7 = {62 43 72 79 70 74 6f 5c 50 72 6f 74 6f 63 6f 6c 5c 5f 73 63 72 79 70 74 2e 70 79 64 } //1 bCrypto\Protocol\_scrypt.pyd
		$a_01_8 = {62 5f 73 6f 63 6b 65 74 2e 70 79 64 } //1 b_socket.pyd
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1) >=18
 
}