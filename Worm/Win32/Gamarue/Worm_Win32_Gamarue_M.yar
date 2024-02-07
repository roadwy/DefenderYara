
rule Worm_Win32_Gamarue_M{
	meta:
		description = "Worm:Win32/Gamarue.M,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {25 73 3f 69 3d 25 73 26 75 3d 25 73 26 6c 3d 25 73 26 66 3d 25 64 26 61 3d 25 73 } //01 00  %s?i=%s&u=%s&l=%s&f=%d&a=%s
		$a_01_1 = {83 e9 0e 74 2d 83 e9 3e 8b 75 14 74 08 81 e9 c4 00 00 00 eb 04 83 7e 08 fb } //00 00 
	condition:
		any of ($a_*)
 
}