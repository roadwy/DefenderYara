
rule TrojanDropper_Win32_Sirefef_A_dll{
	meta:
		description = "TrojanDropper:Win32/Sirefef.A!dll,SIGNATURE_TYPE_ARHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_00_0 = {53 00 79 00 73 00 74 00 65 00 6d 00 00 00 00 00 5c 00 44 00 65 00 76 00 69 00 63 00 65 00 5c 00 5f 00 5f 00 6d 00 61 00 78 00 2b 00 2b 00 3e 00 25 00 77 00 5a 00 00 00 6b 00 65 00 72 00 6e 00 65 00 6c 00 62 00 61 00 73 00 65 00 2e 00 64 00 6c 00 6c 00 00 00 00 00 6b 00 65 00 72 00 6e 00 65 00 6c 00 33 00 32 00 2e 00 64 00 6c 00 6c 00 } //01 00 
		$a_00_1 = {81 39 04 00 00 80 8b 46 04 8b 58 10 0f 85 82 01 00 00 f6 40 14 01 0f 84 78 01 00 00 39 98 c4 00 00 00 0f 83 6c 01 00 00 64 a1 18 00 00 00 3b 58 04 0f 83 5d 01 00 00 81 3b } //00 00 
	condition:
		any of ($a_*)
 
}
rule TrojanDropper_Win32_Sirefef_A_dll_2{
	meta:
		description = "TrojanDropper:Win32/Sirefef.A!dll,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {53 00 79 00 73 00 74 00 65 00 6d 00 00 00 00 00 5c 00 44 00 65 00 76 00 69 00 63 00 65 00 5c 00 5f 00 5f 00 6d 00 61 00 78 00 2b 00 2b 00 3e 00 25 00 77 00 5a 00 00 00 6b 00 65 00 72 00 6e 00 65 00 6c 00 62 00 61 00 73 00 65 00 2e 00 64 00 6c 00 6c 00 00 00 00 00 6b 00 65 00 72 00 6e 00 65 00 6c 00 33 00 32 00 2e 00 64 00 6c 00 6c 00 } //01 00 
		$a_01_1 = {81 39 04 00 00 80 8b 46 04 8b 58 10 0f 85 82 01 00 00 f6 40 14 01 0f 84 78 01 00 00 39 98 c4 00 00 00 0f 83 6c 01 00 00 64 a1 18 00 00 00 3b 58 04 0f 83 5d 01 00 00 81 3b } //00 00 
	condition:
		any of ($a_*)
 
}