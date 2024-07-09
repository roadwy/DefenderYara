
rule PWS_Win32_OnLineGames_KZ{
	meta:
		description = "PWS:Win32/OnLineGames.KZ,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_00_0 = {4b 4a 44 4a 53 4b 4b 57 } //1 KJDJSKKW
		$a_02_1 = {c6 45 e4 6f c6 45 ?? 03 c6 45 ?? 17 c6 45 ?? 1b c6 45 ?? 6d c6 45 ?? 18 c6 45 ?? 0f } //1
	condition:
		((#a_00_0  & 1)*1+(#a_02_1  & 1)*1) >=1
 
}
rule PWS_Win32_OnLineGames_KZ_2{
	meta:
		description = "PWS:Win32/OnLineGames.KZ,SIGNATURE_TYPE_PEHSTR,1d 00 1b 00 08 00 00 "
		
	strings :
		$a_01_0 = {32 33 6c 65 6e 72 65 4b } //10 23lenreK
		$a_01_1 = {74 65 6e 69 6e 69 57 } //10 teniniW
		$a_01_2 = {6d 6f 64 4d 65 73 73 61 67 65 00 6d 6f 64 6d 43 61 6c 6c 62 61 63 6b 00 } //5 潭䵤獥慳敧洀摯䍭污扬捡k
		$a_01_3 = {50 4d 20 56 65 72 69 66 79 21 00 } //5
		$a_01_4 = {25 73 3f 61 31 3d 25 64 26 61 33 3d 25 73 26 61 34 3d 25 73 26 61 36 3d 25 73 00 } //1
		$a_01_5 = {6d 61 70 6c 65 73 74 6f 72 79 2e 65 78 65 } //1 maplestory.exe
		$a_01_6 = {2e 6e 65 78 6f 6e 2e 63 6f 6d } //1 .nexon.com
		$a_01_7 = {44 4e 46 2e 65 78 65 } //1 DNF.exe
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10+(#a_01_2  & 1)*5+(#a_01_3  & 1)*5+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1) >=27
 
}