
rule Ransom_Win32_WannaCrypt_DB_MTB{
	meta:
		description = "Ransom:Win32/WannaCrypt.DB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_81_0 = {57 41 4e 4e 41 43 52 59 } //1 WANNACRY
		$a_81_1 = {2e 77 72 79 } //1 .wry
		$a_81_2 = {43 72 79 70 74 49 6d 70 6f 72 74 4b 65 79 } //1 CryptImportKey
		$a_81_3 = {43 72 79 70 74 44 65 73 74 72 6f 79 4b 65 79 } //1 CryptDestroyKey
		$a_81_4 = {43 72 79 70 74 44 65 63 72 79 70 74 } //1 CryptDecrypt
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1) >=5
 
}