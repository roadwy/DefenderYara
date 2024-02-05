
rule Worm_Win32_Cridex_B{
	meta:
		description = "Worm:Win32/Cridex.B,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 05 00 00 01 00 "
		
	strings :
		$a_02_0 = {73 68 65 6c 6c 5c 90 02 08 5c 63 6f 6d 6d 61 6e 64 3d 25 53 90 00 } //01 00 
		$a_01_1 = {8b c1 33 d2 f7 f3 0f b7 ca 66 83 f9 0a 72 05 83 c1 37 eb 03 83 c1 30 83 ee 01 66 89 4c 77 02 8b c8 79 dd } //01 00 
		$a_01_2 = {8b 50 fc 8b 54 ca 04 83 c1 01 89 3a 3b 08 72 f0 89 78 f8 83 c0 10 39 38 75 } //01 00 
		$a_03_3 = {0f b7 57 38 8b 44 24 10 d1 ea 8d 54 0a 10 3b d0 72 90 01 01 03 c0 90 00 } //01 00 
		$a_01_4 = {83 c1 02 eb 0f 66 83 39 5c 74 09 66 c7 40 02 5c 00 83 c0 02 } //00 00 
	condition:
		any of ($a_*)
 
}