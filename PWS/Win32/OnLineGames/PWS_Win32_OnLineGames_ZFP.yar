
rule PWS_Win32_OnLineGames_ZFP{
	meta:
		description = "PWS:Win32/OnLineGames.ZFP,SIGNATURE_TYPE_PEHSTR_EXT,16 00 16 00 05 00 00 "
		
	strings :
		$a_03_0 = {c6 45 f8 50 c6 45 f9 4f 90 02 10 c6 45 fa 53 c6 45 fb 54 90 00 } //10
		$a_01_1 = {69 c6 45 f6 62 c6 45 f7 61 c6 45 f8 6f c6 45 f9 2e c6 45 fa 61 c6 45 fb 73 c6 45 fc 70 } //10
		$a_00_2 = {25 73 5f 25 64 25 73 00 2e 6a 70 67 } //10 猥╟╤s樮杰
		$a_00_3 = {44 4e 46 2e 65 78 65 } //1 DNF.exe
		$a_00_4 = {51 51 4c 6f 67 69 6e 2e 65 78 65 } //1 QQLogin.exe
	condition:
		((#a_03_0  & 1)*10+(#a_01_1  & 1)*10+(#a_00_2  & 1)*10+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=22
 
}
rule PWS_Win32_OnLineGames_ZFP_2{
	meta:
		description = "PWS:Win32/OnLineGames.ZFP,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 04 00 00 "
		
	strings :
		$a_01_0 = {89 44 24 2e 66 c7 44 24 10 6c 00 66 c7 44 24 12 6f 00 66 c7 44 24 14 67 00 66 c7 44 24 16 69 00 66 c7 44 24 18 6e 00 66 c7 44 24 1a 2e 00 66 c7 44 24 1e 78 00 } //10
		$a_00_1 = {c6 44 24 0d 6c c6 44 24 0e 69 c6 44 24 10 6e c6 44 24 11 74 c6 44 24 12 2e c6 44 24 14 78 } //10
		$a_00_2 = {63 00 68 00 61 00 5f 00 70 00 61 00 73 00 73 00 77 00 6f 00 72 00 64 00 } //1 cha_password
		$a_00_3 = {25 73 3f 73 3d 25 73 26 61 3d 25 73 26 75 3d 25 73 26 70 3d 25 73 26 6e 3d 25 73 26 6c 76 3d 25 64 26 67 3d 25 64 26 79 3d 25 64 26 6c 3d 25 73 26 25 73 3d 25 73 26 25 73 3d 25 73 26 25 73 3d 25 73 26 6d 62 68 3d 25 64 26 73 67 3d 25 64 } //1 %s?s=%s&a=%s&u=%s&p=%s&n=%s&lv=%d&g=%d&y=%d&l=%s&%s=%s&%s=%s&%s=%s&mbh=%d&sg=%d
	condition:
		((#a_01_0  & 1)*10+(#a_00_1  & 1)*10+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=11
 
}