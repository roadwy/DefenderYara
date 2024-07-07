
rule Ransom_Win64_SurtrCrypt_PA_MTB{
	meta:
		description = "Ransom:Win64/SurtrCrypt.PA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_80_0 = {43 72 79 70 74 44 65 63 72 79 70 74 } //CryptDecrypt  1
		$a_80_1 = {50 61 79 6c 6f 61 64 20 73 75 63 63 65 73 73 66 75 6c 6c 79 20 64 65 63 72 79 70 74 65 64 } //Payload successfully decrypted  1
		$a_02_2 = {5c 00 44 00 72 00 6f 00 70 00 70 00 65 00 72 00 5c 00 90 02 04 5c 00 90 02 10 5c 00 44 00 72 00 6f 00 70 00 70 00 65 00 72 00 2e 00 70 00 64 00 62 00 90 00 } //1
		$a_02_3 = {5c 44 72 6f 70 70 65 72 5c 90 02 04 5c 90 02 10 5c 44 72 6f 70 70 65 72 2e 70 64 62 90 00 } //1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_02_2  & 1)*1+(#a_02_3  & 1)*1) >=3
 
}