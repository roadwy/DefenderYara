
rule TrojanDropper_Win32_Bunitu_C{
	meta:
		description = "TrojanDropper:Win32/Bunitu.C,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {50 8b c8 8b 41 3c 8b 54 08 78 03 d1 8b 52 1c 8b 14 11 01 14 24 c3 } //01 00 
		$a_03_1 = {33 c9 51 50 ff 15 90 01 04 33 c9 59 ff e1 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule TrojanDropper_Win32_Bunitu_C_2{
	meta:
		description = "TrojanDropper:Win32/Bunitu.C,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 08 00 00 01 00 "
		
	strings :
		$a_03_0 = {52 4f 46 54 57 41 52 45 5c 4d 69 90 01 04 6f 66 74 5c 58 90 01 01 6e 64 6f 77 73 20 90 01 01 54 5c 43 75 72 90 01 01 65 6e 74 56 65 72 73 69 6f 6e 5c 90 00 } //01 00 
		$a_03_1 = {b8 01 00 00 80 e8 90 01 04 c7 05 90 01 03 00 72 75 6e 64 c7 05 90 01 08 81 2d 90 01 08 66 c7 05 90 01 03 00 20 22 90 00 } //01 00 
		$a_03_2 = {13 81 68 2d 90 01 04 90 03 03 03 ff 48 2d 83 68 2d 90 02 01 e8 90 01 04 b8 02 00 00 80 e8 90 01 04 83 3d 90 01 03 00 02 75 0b 0b c0 75 07 90 00 } //01 00 
		$a_03_3 = {8b fa b9 2c 01 00 00 f2 ae 5a 57 c6 47 ff 22 b0 90 02 10 83 c7 01 8d 35 90 01 04 b9 06 00 00 00 90 00 } //01 00 
		$a_03_4 = {8b f9 2b cf 0f b6 16 03 c2 46 03 d8 8b 90 02 0a bf f1 ff 00 00 90 00 } //01 00 
		$a_03_5 = {d1 e6 87 de 90 01 01 c3 4b 75 fb 5b bf 90 01 04 0f 31 90 03 02 03 d1 c8 c1 c0 03 90 00 } //01 00 
		$a_03_6 = {77 49 45 65 ff 4a 84 07 09 e5 9d 81 00 90 02 20 a8 cc ee 2d 00 00 00 00 90 00 } //01 00 
		$a_01_7 = {77 49 45 65 ff 4a 84 07 09 e5 9d 81 09 a5 a0 81 } //00 00 
		$a_00_8 = {80 } //10 00 
	condition:
		any of ($a_*)
 
}