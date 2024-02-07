
rule PWS_Win32_OnLineGames_CSU{
	meta:
		description = "PWS:Win32/OnLineGames.CSU,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 09 00 00 01 00 "
		
	strings :
		$a_00_0 = {72 73 61 65 6e 68 2e 64 72 73 61 65 6e 68 2e 64 6c 6c } //01 00  rsaenh.drsaenh.dll
		$a_01_1 = {57 72 69 74 65 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79 } //01 00  WriteProcessMemory
		$a_00_2 = {55 70 64 61 74 65 4f 6e 6c 69 6e 65 2e 45 58 45 } //01 00  UpdateOnline.EXE
		$a_00_3 = {54 68 69 6e 67 43 6c 69 65 6e 74 2e 64 6c 6c } //01 00  ThingClient.dll
		$a_00_4 = {2e 5c 51 51 4c 6f 67 69 6e 2e 65 78 65 } //01 00  .\QQLogin.exe
		$a_00_5 = {47 74 53 61 6c 6f 6f 6e 2e 65 78 65 } //01 00  GtSaloon.exe
		$a_00_6 = {51 51 68 78 67 61 6d 65 2e 65 78 65 } //01 00  QQhxgame.exe
		$a_00_7 = {77 6f 77 2e 65 78 65 } //01 00  wow.exe
		$a_00_8 = {43 72 65 61 74 65 54 6f 6f 6c 68 65 6c 70 33 32 53 6e 61 70 73 68 6f 74 } //00 00  CreateToolhelp32Snapshot
	condition:
		any of ($a_*)
 
}