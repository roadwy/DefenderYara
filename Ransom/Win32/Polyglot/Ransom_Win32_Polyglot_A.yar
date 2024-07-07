
rule Ransom_Win32_Polyglot_A{
	meta:
		description = "Ransom:Win32/Polyglot.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {66 75 6e 63 74 69 6f 6e 20 70 72 65 73 73 5f 64 65 6d 6f 5f 64 65 63 72 79 70 74 28 29 0d 0a 7b 0d 0a 09 76 69 73 69 62 6c 65 45 6c 65 6d 65 6e 74 73 28 22 62 5f 64 65 6d 6f 5f 64 65 63 72 79 70 74 22 29 3b } //1
		$a_00_1 = {66 75 6e 63 74 69 6f 6e 20 73 65 74 43 72 79 70 74 65 64 46 69 6c 65 28 73 74 72 46 69 6c 65 73 29 } //1 function setCryptedFile(strFiles)
		$a_01_2 = {66 39 4d fa 76 25 66 0f b6 55 f8 8b 45 fc 8b 75 0c 53 8a 18 32 da 32 d9 66 81 e3 ff 00 41 66 89 1e 40 46 46 66 3b 4d fa 72 e8 5b } //2
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_01_2  & 1)*2) >=3
 
}