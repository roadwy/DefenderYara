
rule PWS_Win32_OnLineGames_CPX{
	meta:
		description = "PWS:Win32/OnLineGames.CPX,SIGNATURE_TYPE_PEHSTR_EXT,7a 00 7a 00 0f 00 00 14 00 "
		
	strings :
		$a_01_0 = {73 74 72 72 63 68 72 } //14 00  strrchr
		$a_01_1 = {43 72 65 61 74 65 54 6f 6f 6c 68 65 6c 70 33 32 53 6e 61 70 73 68 6f 74 } //14 00  CreateToolhelp32Snapshot
		$a_02_2 = {8d bd e0 fe ff ff 83 c9 ff 33 c0 8d 95 d8 fc ff ff f2 ae f7 d1 2b f9 6a 2e 8b c1 8b f7 8b fa c1 e9 02 f3 a5 8b c8 83 e1 03 f3 a4 8d 8d d8 fc ff ff 51 ff 15 90 01 03 00 c6 40 01 00 90 00 } //14 00 
		$a_00_3 = {53 6c 65 65 70 } //14 00  Sleep
		$a_00_4 = {57 72 69 74 65 46 69 6c 65 } //14 00  WriteFile
		$a_00_5 = {57 69 6e 45 78 65 63 } //01 00  WinExec
		$a_00_6 = {90 90 90 8b c9 90 } //01 00 
		$a_00_7 = {90 8b c9 8b d2 90 } //01 00 
		$a_00_8 = {90 8b d2 8b d2 90 } //01 00 
		$a_00_9 = {90 90 8b d2 90 90 } //01 00 
		$a_02_10 = {40 00 ff 15 90 01 03 00 90 90 90 90 90 90 90 90 90 90 90 00 } //01 00 
		$a_02_11 = {6a 00 ff 15 90 01 03 00 90 90 90 90 90 90 90 90 90 00 } //01 00 
		$a_01_12 = {57 90 90 90 90 90 } //01 00 
		$a_00_13 = {90 8b c9 90 8b c9 90 } //01 00 
		$a_00_14 = {8b d2 8b d2 8b d2 90 } //00 00 
	condition:
		any of ($a_*)
 
}