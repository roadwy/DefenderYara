
rule TrojanSpy_Win32_Wekrober_G{
	meta:
		description = "TrojanSpy:Win32/Wekrober.G,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {2a 2e 4a 50 47 00 } //01 00 
		$a_01_1 = {2a 2e 54 58 54 00 } //01 00 
		$a_01_2 = {2a 2e 42 4d 50 00 } //01 00 
		$a_01_3 = {42 6c 6f 71 75 65 61 64 6f 72 20 64 65 20 50 6f 70 2d 75 70 73 00 } //01 00 
		$a_00_4 = {69 66 20 65 78 69 73 74 20 22 25 73 22 20 67 6f 74 6f 20 31 } //01 00 
		$a_01_5 = {6c 69 64 6f 73 20 21 20 2d 20 20 53 65 6e 68 61 20 69 6e 63 6f 72 72 65 74 61 2e } //00 00 
	condition:
		any of ($a_*)
 
}