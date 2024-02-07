
rule Worm_Win32_Autorun_UD{
	meta:
		description = "Worm:Win32/Autorun.UD,SIGNATURE_TYPE_PEHSTR_EXT,06 00 04 00 05 00 00 02 00 "
		
	strings :
		$a_03_0 = {23 c8 85 c9 0f 84 90 01 02 00 00 c7 45 90 01 01 06 00 00 00 66 8b 55 90 01 01 66 83 c2 41 0f bf c2 50 90 00 } //02 00 
		$a_03_1 = {33 d2 83 7d 90 01 01 05 0f 95 c2 f7 da 66 89 55 90 00 } //02 00 
		$a_03_2 = {25 ff 00 00 00 8d 4d 90 01 01 83 f0 01 50 51 ff 15 90 00 } //01 00 
		$a_00_3 = {60 00 74 00 75 00 6e 00 73 00 74 00 6f 00 2f 00 68 00 6f 00 67 00 } //01 00  `tunsto/hog
		$a_00_4 = {5a 00 60 00 74 00 75 00 6e 00 73 00 74 00 6f 00 5c 00 } //00 00  Z`tunsto\
	condition:
		any of ($a_*)
 
}