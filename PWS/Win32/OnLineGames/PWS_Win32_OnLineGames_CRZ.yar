
rule PWS_Win32_OnLineGames_CRZ{
	meta:
		description = "PWS:Win32/OnLineGames.CRZ,SIGNATURE_TYPE_PEHSTR_EXT,20 00 20 00 07 00 00 0a 00 "
		
	strings :
		$a_02_0 = {6a 00 6a 00 6a 00 6a 00 6a 00 6a 00 6a 00 a1 90 01 03 00 50 6a 00 b9 90 01 03 00 ba 90 01 03 00 33 c0 e8 90 01 04 c3 90 00 } //0a 00 
		$a_00_1 = {53 65 74 57 69 6e 64 6f 77 73 48 6f 6f 6b 45 78 41 } //0a 00  SetWindowsHookExA
		$a_00_2 = {4d 73 67 48 6f 6f 6b 4f 6e } //01 00  MsgHookOn
		$a_01_3 = {6c 6f 72 65 00 } //01 00 
		$a_01_4 = {72 2e 45 78 65 00 } //01 00 
		$a_00_5 = {44 45 36 43 42 45 31 37 2d 38 36 39 30 2d 34 38 37 46 2d 41 41 35 44 2d 42 36 42 38 43 39 33 45 45 33 38 41 } //01 00  DE6CBE17-8690-487F-AA5D-B6B8C93EE38A
		$a_00_6 = {3d 7a 68 65 6e 67 64 61 71 69 61 6e 3d } //00 00  =zhengdaqian=
	condition:
		any of ($a_*)
 
}