
rule TrojanSpy_Win32_Banker_NW{
	meta:
		description = "TrojanSpy:Win32/Banker.NW,SIGNATURE_TYPE_PEHSTR,04 00 04 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {45 6d 62 65 64 64 65 64 57 42 20 68 74 74 70 3a 2f 2f 62 73 61 6c 73 61 2e 63 6f 6d 2f } //01 00 
		$a_01_1 = {47 41 52 4f 54 41 2d 4d 41 2e 43 4f 4d } //01 00 
		$a_01_2 = {49 4e 4f 56 41 4e 44 4f 4f 4f 4f 2e 2e 2e } //01 00 
		$a_01_3 = {50 72 6f 6a 65 74 6f 73 5c 4a 61 76 61 5c 42 48 4f 5f 4e 4f 56 4f 5c 75 46 75 6e 63 6f 65 73 2e 70 61 73 } //01 00 
		$a_01_4 = {68 74 74 70 73 3a 2f 2f 61 63 65 73 73 6f 2e 75 6f 6c 2e 63 6f 6d 2e 62 72 2f 6c 6f 67 69 6e 2e 68 74 6d 6c 3f 73 6b 69 6e 3d 77 65 62 6d 61 69 6c } //00 00 
	condition:
		any of ($a_*)
 
}