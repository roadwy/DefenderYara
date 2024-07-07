
rule Ransom_MSIL_FileCryptor_U_MTB{
	meta:
		description = "Ransom:MSIL/FileCryptor.U!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 06 00 00 "
		
	strings :
		$a_81_0 = {76 69 72 75 73 } //1 virus
		$a_81_1 = {66 69 6c 65 45 6e 63 72 79 70 74 65 64 } //1 fileEncrypted
		$a_81_2 = {65 6e 63 72 79 70 74 65 5f 64 65 63 72 79 70 74 65 5f 46 75 6e 63 74 69 6f 6e } //1 encrypte_decrypte_Function
		$a_81_3 = {5c 65 6e 64 6e 5f 6c 6f 67 2e 65 78 65 } //1 \endn_log.exe
		$a_81_4 = {62 79 74 65 73 54 6f 45 6e 63 72 79 70 74 65 64 } //1 bytesToEncrypted
		$a_81_5 = {43 3a 5c 72 32 62 6c 6f 63 6b 5f 57 61 6c 6c 70 61 70 65 72 2e 6a 70 67 } //1 C:\r2block_Wallpaper.jpg
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1) >=5
 
}