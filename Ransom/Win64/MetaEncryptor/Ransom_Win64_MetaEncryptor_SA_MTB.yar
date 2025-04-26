
rule Ransom_Win64_MetaEncryptor_SA_MTB{
	meta:
		description = "Ransom:Win64/MetaEncryptor.SA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {77 65 20 77 69 6c 6c 20 4e 4f 54 20 65 6e 63 72 79 70 74 20 74 68 69 73 20 66 69 6c 65 20 6e 6f 77 20 6f 72 20 6c 61 74 65 72 } //1 we will NOT encrypt this file now or later
		$a_01_1 = {72 65 65 6e 63 72 79 70 74 } //1 reencrypt
		$a_01_2 = {65 6e 63 72 79 70 74 5f 64 65 63 72 79 70 74 5f 64 69 72 65 6e 74 72 79 } //1 encrypt_decrypt_direntry
		$a_01_3 = {72 65 61 64 6d 65 20 66 69 6c 65 20 65 78 69 73 74 73 } //1 readme file exists
		$a_01_4 = {65 78 70 61 6e 64 20 33 32 2d 62 79 74 65 20 6b 65 78 70 61 6e 64 20 33 32 2d 62 79 74 65 } //1 expand 32-byte kexpand 32-byte
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}