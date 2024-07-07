
rule Ransom_MSIL_Sharkcrypt_A_{
	meta:
		description = "Ransom:MSIL/Sharkcrypt.A!!Sharkcrypt.gen!A,SIGNATURE_TYPE_ARHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_00_0 = {3c 65 6e 63 72 79 70 74 5f 64 69 72 65 63 74 6f 72 79 3e 62 5f 5f 30 } //2 <encrypt_directory>b__0
		$a_00_1 = {53 68 61 72 6b 2e 65 78 65 } //2 Shark.exe
		$a_00_2 = {64 65 66 61 75 6c 74 5f 70 72 69 63 65 } //1 default_price
		$a_00_3 = {2e 00 6c 00 6f 00 63 00 6b 00 65 00 64 00 } //1 .locked
		$a_00_4 = {44 00 65 00 63 00 72 00 79 00 70 00 74 00 6f 00 72 00 2e 00 65 00 78 00 65 00 } //1 Decryptor.exe
	condition:
		((#a_00_0  & 1)*2+(#a_00_1  & 1)*2+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=5
 
}