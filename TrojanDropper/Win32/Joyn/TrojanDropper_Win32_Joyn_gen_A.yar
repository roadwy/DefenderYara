
rule TrojanDropper_Win32_Joyn_gen_A{
	meta:
		description = "TrojanDropper:Win32/Joyn.gen!A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_02_0 = {6a 00 68 80 00 00 00 6a 30 6a 30 6a 02 68 00 00 00 40 68 90 01 04 e8 90 00 } //01 00 
		$a_02_1 = {68 04 01 00 00 e8 90 01 04 6a 01 68 90 01 04 6a 00 68 90 01 04 68 90 01 04 6a 90 01 01 e8 90 01 04 b8 01 00 00 00 c9 c2 10 00 90 00 } //01 00 
		$a_03_2 = {4e 00 4a 00 4f 00 59 00 90 02 30 2e 00 4a 00 50 00 47 00 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule TrojanDropper_Win32_Joyn_gen_A_2{
	meta:
		description = "TrojanDropper:Win32/Joyn.gen!A,SIGNATURE_TYPE_PEHSTR_EXT,16 00 12 00 06 00 00 01 00 "
		
	strings :
		$a_00_0 = {45 6e 75 6d 52 65 73 6f 75 72 63 65 4e 61 6d 65 73 41 } //01 00 
		$a_00_1 = {4c 6f 61 64 52 65 73 6f 75 72 63 65 } //01 00 
		$a_00_2 = {53 69 7a 65 6f 66 52 65 73 6f 75 72 63 65 } //04 00 
		$a_00_3 = {00 4f 50 45 4e 00 } //05 00 
		$a_00_4 = {4e 4a 4f 59 00 } //0a 00 
		$a_03_5 = {6a 00 68 80 00 00 00 6a 90 03 01 01 02 30 6a 00 6a 02 68 00 00 00 40 68 90 01 04 e8 90 01 04 89 45 f8 6a 00 8d 45 fc 50 ff 75 e8 ff 75 ec ff 75 f8 e8 90 01 04 ff 75 f8 e8 90 01 04 68 90 01 04 68 04 01 00 00 e8 90 01 04 6a 01 68 90 01 04 6a 00 68 90 01 04 68 90 01 04 6a 00 e8 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}