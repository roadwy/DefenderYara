
rule PWS_Win32_OnLineGames_LN{
	meta:
		description = "PWS:Win32/OnLineGames.LN,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_01_0 = {5f c6 45 f1 5f c6 45 f2 48 c6 45 f3 48 c6 45 f4 45 c6 45 f5 58 c6 45 f6 45 c6 45 f7 4d c6 45 f8 55 c6 45 f9 54 c6 45 fa 45 c6 45 fb 58 c6 45 fc 5f c6 45 fd 5f } //3
		$a_03_1 = {73 50 8d 85 ?? ?? ?? ?? [0-01] c6 45 ?? 6b c6 45 ?? 69 c6 45 ?? 6c c6 45 ?? 6c } //1
		$a_02_2 = {5c 88 5d ff [0-01] c6 45 ?? 64 c6 45 ?? 65 c6 45 ?? 6c c6 45 ?? 73 c6 45 ?? 65 c6 45 ?? 6c c6 45 ?? 66 c6 45 ?? 2e c6 45 ?? 62 } //1
		$a_03_3 = {47 50 6a 00 68 03 00 1f 00 c6 ?? f1 6c c6 ?? f2 6f c6 ?? f3 62 c6 ?? f4 61 c6 ?? f5 6c c6 ?? f6 5c c6 ?? f7 45 c6 ?? f8 6e c6 ?? f9 78 } //2
	condition:
		((#a_01_0  & 1)*3+(#a_03_1  & 1)*1+(#a_02_2  & 1)*1+(#a_03_3  & 1)*2) >=3
 
}