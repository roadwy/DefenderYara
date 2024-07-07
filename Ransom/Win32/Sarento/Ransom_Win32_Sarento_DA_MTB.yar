
rule Ransom_Win32_Sarento_DA_MTB{
	meta:
		description = "Ransom:Win32/Sarento.DA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 "
		
	strings :
		$a_01_0 = {45 6e 63 72 79 70 74 6f 72 20 52 61 61 53 20 44 65 63 72 79 70 74 6f 72 } //1 Encryptor RaaS Decryptor
		$a_01_1 = {54 68 69 73 20 66 69 6c 65 20 69 73 20 73 75 70 70 6f 73 65 64 20 74 6f 20 61 6e 6f 74 68 65 72 20 73 79 73 74 65 6d 21 } //1 This file is supposed to another system!
		$a_01_2 = {59 6f 75 72 20 73 79 73 74 65 6d 20 6d 61 79 20 6e 6f 74 20 62 65 20 63 6f 6e 6e 65 63 74 65 64 20 74 6f 20 74 68 65 20 69 6e 74 65 72 6e 65 74 2e } //1 Your system may not be connected to the internet.
		$a_01_3 = {77 00 61 00 6c 00 6c 00 65 00 74 00 } //1 wallet
		$a_01_4 = {46 69 6e 64 4e 65 78 74 46 69 6c 65 57 } //1 FindNextFileW
		$a_01_5 = {53 65 74 45 6e 64 4f 66 46 69 6c 65 } //1 SetEndOfFile
		$a_01_6 = {57 72 69 74 65 46 69 6c 65 } //1 WriteFile
		$a_01_7 = {44 65 6c 65 74 65 46 69 6c 65 57 } //1 DeleteFileW
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1) >=8
 
}