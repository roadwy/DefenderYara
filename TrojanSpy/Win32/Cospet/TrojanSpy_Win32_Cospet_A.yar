
rule TrojanSpy_Win32_Cospet_A{
	meta:
		description = "TrojanSpy:Win32/Cospet.A,SIGNATURE_TYPE_PEHSTR,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {53 65 74 20 4d 79 53 68 65 6c 6c 20 3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 57 73 63 72 69 70 74 2e 53 68 65 6c 6c 22 29 } //01 00 
		$a_01_1 = {5c 41 75 74 6f 72 75 6e 2e 76 62 73 } //01 00 
		$a_01_2 = {68 74 74 70 3a 2f 2f 63 68 65 63 6b 69 70 2e 64 79 6e 64 6e 73 2e 6f 72 67 } //01 00 
		$a_01_3 = {22 23 53 74 65 61 6d 5f 4c 6f 67 69 6e 5f 52 65 6d 65 6d 62 65 72 50 61 73 73 77 6f 72 64 22 } //00 00 
	condition:
		any of ($a_*)
 
}