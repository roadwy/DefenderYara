
rule TrojanDropper_Win32_Monkif_B{
	meta:
		description = "TrojanDropper:Win32/Monkif.B,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 06 00 00 02 00 "
		
	strings :
		$a_01_0 = {81 7d f4 93 08 00 00 74 0c 46 81 fe e8 19 10 00 7c } //02 00 
		$a_00_1 = {51 72 6f 63 65 73 73 33 32 46 69 72 73 74 00 00 5a 72 6f 63 65 73 73 33 32 4e 65 78 74 } //01 00 
		$a_00_2 = {00 4c 6f 63 61 6c 5c 55 49 45 49 00 } //01 00 
		$a_00_3 = {2e 62 61 6b 00 71 71 25 73 } //01 00 
		$a_00_4 = {6d 6f 6e 6b 65 79 2e 67 69 66 00 } //01 00 
		$a_01_5 = {45 d1 4c c6 45 d2 64 c6 45 d3 74 c6 45 d4 45 c6 45 d5 6e c6 45 d6 74 c6 45 d7 72 c6 45 d8 69 c6 45 d9 65 c6 45 da 73 } //00 00 
	condition:
		any of ($a_*)
 
}