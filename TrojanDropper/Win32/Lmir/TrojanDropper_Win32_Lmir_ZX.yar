
rule TrojanDropper_Win32_Lmir_ZX{
	meta:
		description = "TrojanDropper:Win32/Lmir.ZX,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {44 65 73 6b 74 6f 70 00 00 5c 64 6c 6c 63 61 63 68 65 5c 76 65 72 63 6c 73 69 64 2e 65 78 65 } //1
		$a_01_1 = {5c 76 65 72 63 6c 73 69 64 2e 65 78 65 00 00 00 78 70 6c 6f 72 65 72 2e 65 78 65 } //1
		$a_01_2 = {63 6c 69 65 6e 74 2e 65 78 65 00 00 77 69 6e 6e 74 00 00 00 77 69 6e 64 6f 77 73 00 73 79 73 74 } //1
		$a_01_3 = {73 79 73 74 65 6d 33 32 00 00 00 00 53 65 44 65 } //1
		$a_01_4 = {51 8d 44 24 00 6a 00 50 6a 00 68 3f 00 0f 00 6a 00 6a 00 6a 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}