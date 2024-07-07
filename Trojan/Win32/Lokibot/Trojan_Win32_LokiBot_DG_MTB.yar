
rule Trojan_Win32_LokiBot_DG_MTB{
	meta:
		description = "Trojan:Win32/LokiBot.DG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {be 01 00 00 00 90 05 10 01 90 8b d0 03 d6 90 05 10 01 90 c6 02 59 90 05 10 01 90 46 81 fe a5 a6 f1 22 75 eb 90 00 } //1
		$a_03_1 = {33 c0 89 07 90 02 40 b3 90 01 01 90 05 10 01 90 a3 90 01 04 90 05 10 01 90 8b c6 90 05 10 01 90 8a 80 90 01 04 a2 90 01 04 90 05 10 01 90 8b d3 a0 90 01 04 e8 90 01 04 a2 90 01 04 90 05 10 01 90 8a 1d 90 01 04 90 05 10 01 90 8b c3 e8 90 01 04 90 05 10 01 90 8b 07 90 05 10 01 90 40 89 07 90 05 10 01 90 46 81 fe 90 01 04 75 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}
rule Trojan_Win32_LokiBot_DG_MTB_2{
	meta:
		description = "Trojan:Win32/LokiBot.DG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_81_0 = {66 78 79 79 62 62 } //1 fxyybb
		$a_03_1 = {5c 54 45 4d 50 5c 6e 73 90 02 0f 2e 74 6d 70 5c 90 02 0f 2e 64 6c 6c 90 00 } //1
		$a_81_2 = {75 6e 6b 6e 6f 77 6e 64 6c 6c 2e 70 64 62 } //1 unknowndll.pdb
		$a_03_3 = {5c 4c 6f 61 64 65 72 5c 90 02 0f 5c 52 65 6c 65 61 73 65 5c 90 02 0f 2e 70 64 62 90 00 } //1
		$a_81_4 = {75 6e 68 61 6e 64 6c 65 64 20 61 6c 67 6f 72 69 74 68 6d } //1 unhandled algorithm
		$a_81_5 = {56 32 43 41 50 49 44 53 41 50 52 49 56 41 54 45 42 4c 4f 42 } //1 V2CAPIDSAPRIVATEBLOB
		$a_81_6 = {54 6f 6f 6c 68 65 6c 70 33 32 52 65 61 64 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79 } //1 Toolhelp32ReadProcessMemory
	condition:
		((#a_81_0  & 1)*1+(#a_03_1  & 1)*1+(#a_81_2  & 1)*1+(#a_03_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1) >=7
 
}