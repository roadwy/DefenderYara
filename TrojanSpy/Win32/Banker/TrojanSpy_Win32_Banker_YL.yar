
rule TrojanSpy_Win32_Banker_YL{
	meta:
		description = "TrojanSpy:Win32/Banker.YL,SIGNATURE_TYPE_PEHSTR_EXT,08 00 06 00 04 00 00 05 00 "
		
	strings :
		$a_01_0 = {4c 6f 67 69 6e 4d 61 69 6c 45 58 58 30 30 38 39 } //01 00 
		$a_01_1 = {72 65 64 65 5f 64 65 5f 64 61 64 6f 73 } //01 00 
		$a_01_2 = {57 57 57 5f 47 65 74 57 69 6e 64 6f 77 49 6e 66 6f } //01 00 
		$a_01_3 = {62 72 61 73 69 6c 69 6e 73 74 72 75 6d 65 6e 74 61 6c 2e 63 6f 6d 2e 62 72 2f 65 6e 76 69 6f 58 2e 70 68 70 } //00 00 
	condition:
		any of ($a_*)
 
}