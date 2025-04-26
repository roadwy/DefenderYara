
rule PWS_Win32_OnLineGames_IY_dll{
	meta:
		description = "PWS:Win32/OnLineGames.IY!dll,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {c6 44 24 2c 52 c6 44 24 2e 61 c6 44 24 2f 64 c6 44 24 30 46 88 4c 24 31 c6 44 24 32 6c 88 5c 24 34 } //1
		$a_01_1 = {b2 72 b0 65 51 56 c6 44 24 18 5c c6 44 24 19 63 c6 44 24 1a 78 88 54 24 1b c6 44 24 1c 2e } //1
		$a_01_2 = {25 73 26 6a 62 3d 25 73 26 79 3d 25 73 } //1 %s&jb=%s&y=%s
		$a_01_3 = {25 73 3f 61 3d 25 73 26 73 3d 25 73 26 75 3d 25 73 26 70 3d 25 73 26 6a 73 3d 25 73 26 64 6a 3d 25 73 26 6c 3d 25 73 26 6d 62 3d 25 73 } //1 %s?a=%s&s=%s&u=%s&p=%s&js=%s&dj=%s&l=%s&mb=%s
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}