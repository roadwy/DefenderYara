
rule Ransom_Linux_Cryptor_B_MTB{
	meta:
		description = "Ransom:Linux/Cryptor.B!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {6d 61 69 6e 2e 65 6e 63 72 79 70 74 } //2 main.encrypt
		$a_00_1 = {71 6e 61 70 5f 63 72 79 70 74 5f 77 6f 72 6b 65 72 } //2 qnap_crypt_worker
		$a_00_2 = {43 68 30 72 61 69 78 } //1 Ch0raix
		$a_00_3 = {41 6c 6c 20 79 6f 75 72 20 64 61 74 61 20 68 61 73 20 62 65 65 6e 20 6c 6f 63 6b 65 64 28 63 72 79 70 74 65 64 } //1 All your data has been locked(crypted
	condition:
		((#a_00_0  & 1)*2+(#a_00_1  & 1)*2+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}