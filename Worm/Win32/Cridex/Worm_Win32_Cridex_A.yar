
rule Worm_Win32_Cridex_A{
	meta:
		description = "Worm:Win32/Cridex.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_02_0 = {73 68 65 6c 6c 5c 90 02 08 5c 63 6f 6d 6d 61 6e 64 3d 25 53 90 00 } //01 00 
		$a_03_1 = {68 01 00 00 80 e8 90 01 04 83 c4 24 85 c0 75 c0 e8 90 01 04 33 c0 90 00 } //01 00 
		$a_03_2 = {c1 e2 10 0b d1 89 15 90 01 04 0f b7 94 24 90 01 02 00 00 c1 e2 10 0b d0 89 15 90 01 04 e8 90 01 04 33 d2 b9 e8 03 00 00 f7 f1 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}