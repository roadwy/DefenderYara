
rule Ransom_MSIL_Jcrypt_DC_MTB{
	meta:
		description = "Ransom:MSIL/Jcrypt.DC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 06 00 00 "
		
	strings :
		$a_81_0 = {52 45 43 4f 56 45 52 5f 5f 46 49 4c 45 53 } //2 RECOVER__FILES
		$a_81_1 = {45 6e 63 72 79 70 74 69 6e 67 } //2 Encrypting
		$a_81_2 = {4e 6f 20 66 69 6c 65 73 20 74 6f 20 65 6e 63 72 79 70 74 } //2 No files to encrypt
		$a_81_3 = {2e 6a 63 72 79 70 74 } //1 .jcrypt
		$a_81_4 = {2e 77 61 6e 6e 61 70 61 79 } //1 .wannapay
		$a_81_5 = {2e 64 61 64 64 79 63 72 79 70 74 } //1 .daddycrypt
	condition:
		((#a_81_0  & 1)*2+(#a_81_1  & 1)*2+(#a_81_2  & 1)*2+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1) >=7
 
}