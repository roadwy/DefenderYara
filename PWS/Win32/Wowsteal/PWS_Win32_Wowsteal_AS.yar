
rule PWS_Win32_Wowsteal_AS{
	meta:
		description = "PWS:Win32/Wowsteal.AS,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 01 00 "
		
	strings :
		$a_03_0 = {68 24 08 00 00 50 ff 15 90 01 04 8a 45 0b 83 c4 14 8d 4d 90 00 } //01 00 
		$a_01_1 = {80 7d de e8 74 18 80 7d de e9 74 12 0f b6 45 de 3d 84 0f 00 00 74 07 3d 85 0f 00 00 75 13 } //01 00 
		$a_01_2 = {25 73 2f 63 2e 61 73 70 3f 63 3d 71 26 69 3d 25 73 00 } //01 00 
		$a_01_3 = {26 75 3d 25 73 26 70 3d 25 73 26 73 70 3d 25 73 26 6d 62 3d 25 73 26 72 3d 25 73 26 6c 3d 25 64 26 6d 3d 25 64 00 } //00 00 
	condition:
		any of ($a_*)
 
}