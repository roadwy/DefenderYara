
rule PWS_Win32_OnLineGames_MY{
	meta:
		description = "PWS:Win32/OnLineGames.MY,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_03_0 = {01 00 4d c6 05 ?? ?? 01 00 41 c6 05 ?? ?? 01 00 50 68 ?? ?? 01 00 c6 05 ?? ?? 01 00 44 c6 05 ?? ?? 01 00 4e c6 05 ?? ?? 01 00 46 90 09 04 00 c6 05 } //1
		$a_00_1 = {41 48 4e 4c 45 53 54 4f 52 59 2e 45 58 45 } //1 AHNLESTORY.EXE
		$a_00_2 = {57 4f 57 2e 45 58 45 } //1 WOW.EXE
		$a_00_3 = {44 49 41 42 4c 4f 20 49 49 49 2e 45 58 45 } //1 DIABLO III.EXE
	condition:
		((#a_03_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}