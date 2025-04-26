
rule PWS_Win32_OnLineGames_ZDM_dll{
	meta:
		description = "PWS:Win32/OnLineGames.ZDM!dll,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_03_0 = {c7 04 24 b8 0b 00 00 ff 15 ?? ?? ?? ?? e9 ?? ?? ?? ?? 55 8b ec 8b c9 8b d2 8b c9 8b c0 90 90 8b c9 } //1
		$a_03_1 = {8d 85 e0 fd ff ff 50 c6 45 ?? 25 c6 45 ?? 73 c6 45 ?? 3f c6 45 ?? 61 c6 45 ?? 63 c6 45 ?? 74 c6 45 ?? 69 c6 45 ?? 6f c6 45 ?? ?? ?? ?? ?? 3d } //1
		$a_03_2 = {8b c9 33 db c6 45 ?? 45 c6 45 ?? 78 c6 45 ?? 70 c6 45 ?? 6c c6 45 ?? 6f c6 45 ?? 72 c6 45 ?? 65 c6 45 ?? 72 c6 45 ?? 2e } //1
		$a_01_3 = {3f 61 3d 25 73 26 73 3d b5 da 28 25 64 29 b7 fe 26 75 3d 25 73 26 70 3d 25 73 26 72 3d 25 73 26 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}