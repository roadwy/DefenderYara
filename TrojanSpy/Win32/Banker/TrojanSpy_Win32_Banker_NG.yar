
rule TrojanSpy_Win32_Banker_NG{
	meta:
		description = "TrojanSpy:Win32/Banker.NG,SIGNATURE_TYPE_PEHSTR,16 00 16 00 05 00 00 0a 00 "
		
	strings :
		$a_01_0 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e } //0a 00 
		$a_01_1 = {60 7c 7c 78 32 27 27 } //01 00 
		$a_01_2 = {5c 73 65 37 74 69 6e 67 73 2e 73 30 6c 00 } //01 00 
		$a_01_3 = {5c 64 6f 77 6e 6c 30 61 64 2e 74 72 61 63 6b 00 } //01 00 
		$a_01_4 = {5c 6e 6f 74 69 2e 66 79 00 } //00 00 
	condition:
		any of ($a_*)
 
}