
rule Worm_Win32_EyeStye_B{
	meta:
		description = "Worm:Win32/EyeStye.B,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {8a 06 3c 41 88 44 24 14 0f 84 89 00 00 00 3c 61 0f 84 81 00 00 00 3c 62 74 7d 90 01 1c ff d7 83 f8 02 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Worm_Win32_EyeStye_B_2{
	meta:
		description = "Worm:Win32/EyeStye.B,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {42 61 73 69 63 20 55 53 42 20 53 70 72 65 61 64 20 3a 20 53 70 72 65 61 64 69 6e 67 20 22 25 73 22 20 41 73 20 22 25 73 22 } //01 00 
		$a_01_1 = {49 6e 66 65 63 74 65 64 20 44 72 69 76 65 28 73 29 } //01 00 
		$a_00_2 = {25 73 5c 61 75 74 6f 72 75 6e 2e 69 6e 69 } //00 00 
	condition:
		any of ($a_*)
 
}