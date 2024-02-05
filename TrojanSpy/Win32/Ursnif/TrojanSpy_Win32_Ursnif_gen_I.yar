
rule TrojanSpy_Win32_Ursnif_gen_I{
	meta:
		description = "TrojanSpy:Win32/Ursnif.gen!I,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {74 26 8b 45 d4 c6 00 e9 8b 4f 14 2b c8 83 e9 05 } //01 00 
		$a_03_1 = {8b 04 b7 3b 05 90 01 04 74 11 3b 45 ec 74 0c 8b 4d f4 50 6a 04 58 e8 90 01 04 46 3b 75 fc 72 de 90 00 } //01 00 
		$a_00_2 = {4e 45 57 47 52 41 42 00 67 72 61 62 73 3d 00 } //01 00 
		$a_00_3 = {2f 66 70 20 25 6c 75 00 44 4c 5f 45 58 45 00 00 44 4c 5f 45 58 45 5f 53 54 00 } //01 00 
		$a_00_4 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 49 6e 65 74 44 61 74 61 00 } //00 00 
	condition:
		any of ($a_*)
 
}