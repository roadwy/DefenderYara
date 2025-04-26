
rule Ransom_MSIL_FileCryptor_T_MTB{
	meta:
		description = "Ransom:MSIL/FileCryptor.T!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 05 00 00 "
		
	strings :
		$a_81_0 = {2e 65 6e 63 } //1 .enc
		$a_81_1 = {4b 72 79 70 74 61 20 44 65 63 72 79 70 74 65 64 } //1 Krypta Decrypted
		$a_81_2 = {5c 53 74 61 72 74 75 70 5c 77 69 6e 33 32 2e 65 78 65 } //1 \Startup\win32.exe
		$a_81_3 = {41 6c 6c 20 66 69 6c 65 73 20 68 61 76 65 20 62 65 65 6e 20 64 65 63 72 79 70 74 65 64 } //1 All files have been decrypted
		$a_81_4 = {52 61 6e 73 6f 6d 65 } //1 Ransome
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1) >=4
 
}