
rule Ransom_MSIL_CriseCrypt_DA_MTB{
	meta:
		description = "Ransom:MSIL/CriseCrypt.DA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_81_0 = {63 72 69 73 65 2d 63 72 79 70 74 } //1 crise-crypt
		$a_81_1 = {53 74 61 72 74 69 6e 67 20 65 6e 63 72 79 70 74 69 6f 6e } //1 Starting encryption
		$a_81_2 = {2f 43 20 4e 65 74 53 68 20 41 64 76 66 69 72 65 77 61 6c 6c 20 73 65 74 20 61 6c 6c 70 72 6f 66 69 6c 65 73 20 73 74 61 74 65 20 6f 66 66 } //1 /C NetSh Advfirewall set allprofiles state off
		$a_81_3 = {2e 63 6f 6d 70 72 65 73 73 65 64 } //1 .compressed
		$a_81_4 = {63 6f 73 74 75 72 61 } //1 costura
		$a_81_5 = {2e 63 72 79 70 74 } //1 .crypt
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1) >=6
 
}