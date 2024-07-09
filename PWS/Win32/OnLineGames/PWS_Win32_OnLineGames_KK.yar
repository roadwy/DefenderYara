
rule PWS_Win32_OnLineGames_KK{
	meta:
		description = "PWS:Win32/OnLineGames.KK,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 05 00 00 "
		
	strings :
		$a_01_0 = {c6 45 f4 25 c6 45 f5 73 c6 45 f6 26 c6 45 f7 70 c6 45 f8 73 c6 45 f9 3d c6 45 fa 25 c6 45 fb 73 ff 15 } //1
		$a_01_1 = {80 65 ff 00 c6 45 f8 77 c6 45 f9 6f c6 45 fa 77 c6 45 fb 2e c6 45 fc 65 c6 45 fd 78 c6 45 fe 65 e8 } //1
		$a_03_2 = {74 50 68 04 01 00 00 c6 45 ?? 74 c6 45 ?? 63 c6 45 ?? 65 c6 45 ?? 72 c6 45 ?? 67 c6 45 ?? 2e } //1
		$a_03_3 = {57 50 c6 45 ?? 54 c6 45 ?? 46 c6 45 ?? 5c c6 45 ?? 43 c6 45 ?? 6f c6 45 ?? 6e c6 45 ?? 66 } //1
		$a_03_4 = {6a 03 53 6a 01 66 ab 68 00 00 00 80 c6 45 ?? 72 ff 75 08 c6 45 ?? 65 aa c6 45 ?? 61 c6 45 ?? 6c c6 45 ?? 6d } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1+(#a_03_3  & 1)*1+(#a_03_4  & 1)*1) >=2
 
}