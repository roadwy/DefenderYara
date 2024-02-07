
rule PWS_Win32_OnLineGames_ZDX_dll{
	meta:
		description = "PWS:Win32/OnLineGames.ZDX!dll,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 05 00 00 01 00 "
		
	strings :
		$a_03_0 = {68 80 3e 00 00 ff 15 24 19 00 10 e9 4b ff ff ff e8 90 01 04 e8 90 01 04 f7 d8 1b c0 40 c3 90 00 } //01 00 
		$a_03_1 = {57 56 c6 45 90 01 01 8b c6 45 90 01 01 4d c6 45 90 01 01 0c c6 45 90 01 01 8b c6 45 90 01 01 75 c6 45 90 01 01 10 c6 45 90 01 01 8a c6 45 90 01 01 45 c6 45 90 01 01 18 e8 90 00 } //01 00 
		$a_01_2 = {75 70 2f 55 70 66 2e 61 73 70 } //01 00  up/Upf.asp
		$a_01_3 = {25 73 25 73 3f 61 63 3d 68 26 69 3d 25 73 26 68 3d 25 73 } //01 00  %s%s?ac=h&i=%s&h=%s
		$a_01_4 = {25 73 25 73 3f 63 3d 71 26 69 3d 25 73 26 73 3d 25 73 26 61 3d 25 73 26 6d 3d 25 73 26 74 3d 25 64 } //00 00  %s%s?c=q&i=%s&s=%s&a=%s&m=%s&t=%d
	condition:
		any of ($a_*)
 
}