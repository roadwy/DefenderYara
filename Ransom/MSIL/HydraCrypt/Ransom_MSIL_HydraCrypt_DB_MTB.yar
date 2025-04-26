
rule Ransom_MSIL_HydraCrypt_DB_MTB{
	meta:
		description = "Ransom:MSIL/HydraCrypt.DB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_81_0 = {44 69 72 65 63 74 6f 72 79 5f 65 6e 63 72 79 70 74 6f 72 } //1 Directory_encryptor
		$a_81_1 = {43 72 65 61 74 65 45 6e 63 72 79 70 74 6f 72 } //1 CreateEncryptor
		$a_81_2 = {67 65 74 5f 45 78 74 65 6e 73 69 6f 6e } //1 get_Extension
		$a_81_3 = {45 6e 63 72 79 70 74 44 69 72 } //1 EncryptDir
		$a_81_4 = {45 6e 63 72 79 70 74 46 69 6c 65 } //1 EncryptFile
		$a_81_5 = {53 6c 65 65 70 } //1 Sleep
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1) >=6
 
}