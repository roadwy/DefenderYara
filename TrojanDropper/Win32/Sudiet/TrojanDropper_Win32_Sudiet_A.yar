
rule TrojanDropper_Win32_Sudiet_A{
	meta:
		description = "TrojanDropper:Win32/Sudiet.A,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 04 00 "
		
	strings :
		$a_03_0 = {8a c8 80 c1 90 01 01 30 88 90 01 04 40 3d 90 01 04 72 ed b8 90 00 } //01 00 
		$a_00_1 = {5c 00 54 00 44 00 4b 00 44 00 } //01 00 
		$a_00_2 = {74 00 64 00 73 00 73 00 73 00 65 00 72 00 76 00 } //01 00 
		$a_00_3 = {74 00 64 00 73 00 73 00 64 00 61 00 74 00 61 00 } //01 00 
		$a_00_4 = {74 00 64 00 73 00 73 00 63 00 6d 00 64 00 } //00 00 
	condition:
		any of ($a_*)
 
}