
rule PWS_Win32_OnLineGames_ZDM_dll{
	meta:
		description = "PWS:Win32/OnLineGames.ZDM!dll,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_03_0 = {c7 04 24 b8 0b 00 00 ff 15 90 01 04 e9 90 01 04 55 8b ec 8b c9 8b d2 8b c9 8b c0 90 90 8b c9 90 00 } //01 00 
		$a_03_1 = {8d 85 e0 fd ff ff 50 c6 45 90 01 01 25 c6 45 90 01 01 73 c6 45 90 01 01 3f c6 45 90 01 01 61 c6 45 90 01 01 63 c6 45 90 01 01 74 c6 45 90 01 01 69 c6 45 90 01 01 6f c6 45 90 01 05 3d 90 00 } //01 00 
		$a_03_2 = {8b c9 33 db c6 45 90 01 01 45 c6 45 90 01 01 78 c6 45 90 01 01 70 c6 45 90 01 01 6c c6 45 90 01 01 6f c6 45 90 01 01 72 c6 45 90 01 01 65 c6 45 90 01 01 72 c6 45 90 01 01 2e 90 00 } //01 00 
		$a_01_3 = {3f 61 3d 25 73 26 73 3d b5 da 28 25 64 29 b7 fe 26 75 3d 25 73 26 70 3d 25 73 26 72 3d 25 73 26 } //00 00 
	condition:
		any of ($a_*)
 
}