
rule PWS_Win32_Frethog_BL{
	meta:
		description = "PWS:Win32/Frethog.BL,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 07 00 00 02 00 "
		
	strings :
		$a_03_0 = {76 32 c6 06 25 46 0f b6 07 50 8d 45 90 01 01 68 90 01 04 50 ff 15 90 01 04 66 8b 45 90 00 } //02 00 
		$a_01_1 = {c6 07 e8 2b c7 83 e8 05 89 47 01 8a 45 0b 3c 68 88 47 05 74 0e 3c a3 74 0a } //02 00 
		$a_01_2 = {2b f7 89 47 06 83 ee 0a c6 47 0a e9 89 77 0b 5f 5e } //01 00 
		$a_00_3 = {25 73 5c 64 6c 6c 63 61 63 68 65 5c 25 73 2e 6a 70 67 } //01 00 
		$a_00_4 = {6d 69 62 61 6f 2e 61 73 70 } //01 00 
		$a_00_5 = {25 73 3f 61 63 74 3d 67 65 74 70 6f 73 26 64 31 30 3d 25 73 26 70 6f 73 3d 26 64 38 30 3d } //01 00 
		$a_00_6 = {25 73 25 73 25 73 2d 25 64 2e 62 6d 70 } //00 00 
	condition:
		any of ($a_*)
 
}