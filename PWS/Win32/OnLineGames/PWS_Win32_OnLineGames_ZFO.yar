
rule PWS_Win32_OnLineGames_ZFO{
	meta:
		description = "PWS:Win32/OnLineGames.ZFO,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {43 4d 44 5f 53 4f 46 54 4b 45 59 44 4f 57 4e } //01 00  CMD_SOFTKEYDOWN
		$a_01_1 = {3d 45 59 45 59 75 } //01 00  =EYEYu
		$a_00_2 = {44 4e 46 2e 65 78 65 } //01 00  DNF.exe
		$a_01_3 = {80 3b 2f 75 08 80 7b 01 2f 75 02 43 43 } //03 00 
		$a_01_4 = {c6 45 f4 6d c6 45 f5 69 c6 45 f6 62 c6 45 f7 61 c6 45 f8 6f c6 45 f9 2e c6 45 fa 61 c6 45 fb 73 c6 45 fc 70 } //00 00 
	condition:
		any of ($a_*)
 
}