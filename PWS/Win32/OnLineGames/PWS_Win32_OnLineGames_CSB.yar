
rule PWS_Win32_OnLineGames_CSB{
	meta:
		description = "PWS:Win32/OnLineGames.CSB,SIGNATURE_TYPE_PEHSTR_EXT,16 00 16 00 06 00 00 0a 00 "
		
	strings :
		$a_02_0 = {75 26 8d 94 24 90 01 02 00 00 68 04 01 00 00 52 ff d6 6a 00 ff d7 8b 44 24 90 01 01 50 6a 00 68 ff 0f 1f 00 ff d3 6a 00 50 ff d5 8d 4c 24 90 01 01 68 90 01 03 00 51 ff 15 90 01 03 00 90 00 } //0a 00 
		$a_00_1 = {43 72 65 61 74 65 54 6f 6f 6c 68 65 6c 70 33 32 53 6e 61 70 73 68 6f 74 } //02 00  CreateToolhelp32Snapshot
		$a_00_2 = {00 61 76 70 2e 65 78 65 } //01 00  愀灶攮數
		$a_00_3 = {33 36 30 53 61 66 65 2e 65 78 65 } //01 00  360Safe.exe
		$a_00_4 = {69 66 20 65 78 69 73 74 20 22 25 73 22 20 67 6f 74 6f 20 52 65 70 65 61 74 } //01 00  if exist "%s" goto Repeat
		$a_00_5 = {64 65 6c 20 22 25 73 22 } //00 00  del "%s"
	condition:
		any of ($a_*)
 
}