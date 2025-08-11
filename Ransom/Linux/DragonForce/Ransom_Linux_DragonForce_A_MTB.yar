
rule Ransom_Linux_DragonForce_A_MTB{
	meta:
		description = "Ransom:Linux/DragonForce.A!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {65 6e 63 72 79 70 74 65 64 5f 6e 6f 74 65 } //1 encrypted_note
		$a_01_1 = {76 69 6d 2d 63 6d 64 20 76 6d 73 76 63 2f 67 65 74 61 6c 6c 76 6d 73 } //1 vim-cmd vmsvc/getallvms
		$a_01_2 = {45 43 52 59 50 54 5f 65 6e 63 72 79 70 74 5f 62 79 74 65 73 } //1 ECRYPT_encrypt_bytes
		$a_01_3 = {76 69 6d 2d 63 6d 64 20 76 6d 73 76 63 2f 70 6f 77 65 72 2e 6f 66 66 } //1 vim-cmd vmsvc/power.off
		$a_01_4 = {6c 6f 67 67 65 72 5f 65 6e 63 72 79 70 74 69 6f 6e 2e 63 70 70 } //1 logger_encryption.cpp
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}