
rule Ransom_Win32_Filecoder_LM_MTB{
	meta:
		description = "Ransom:Win32/Filecoder.LM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 05 00 00 "
		
	strings :
		$a_81_0 = {54 72 79 20 74 6f 20 65 6e 63 72 79 70 74 20 73 65 6c 65 63 74 65 64 20 6f 62 6a 65 63 74 73 } //1 Try to encrypt selected objects
		$a_81_1 = {45 6e 63 72 79 70 74 69 6f 6e 20 69 6e 20 66 61 73 74 20 6d 6f 64 65 } //2 Encryption in fast mode
		$a_81_2 = {45 6e 63 72 79 70 74 69 6f 6e 20 63 6f 6d 70 6c 65 74 65 64 2e } //3 Encryption completed.
		$a_81_3 = {52 65 61 64 79 20 74 6f 20 73 63 61 6e 20 66 6f 6c 64 65 72 73 20 61 6e 64 20 66 69 6c 65 73 20 65 6e 63 72 79 70 74 69 6f 6e 2e } //4 Ready to scan folders and files encryption.
		$a_01_4 = {44 8b 55 0c 46 33 94 c9 10 02 00 00 44 89 55 30 4c 8b ca 4d 03 c9 4d 03 c9 44 8b 55 10 46 33 94 c9 14 02 00 00 44 89 55 34 4c 8b ca 4d 03 c9 4d 03 c9 44 8b 55 14 46 33 94 c9 18 02 00 00 44 89 55 38 48 03 d2 } //10
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*2+(#a_81_2  & 1)*3+(#a_81_3  & 1)*4+(#a_01_4  & 1)*10) >=20
 
}