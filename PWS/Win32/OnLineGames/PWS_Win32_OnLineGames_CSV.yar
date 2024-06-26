
rule PWS_Win32_OnLineGames_CSV{
	meta:
		description = "PWS:Win32/OnLineGames.CSV,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 01 00 "
		
	strings :
		$a_02_0 = {55 8b ec 81 ec 84 00 00 00 56 ff 15 90 01 04 8b f0 85 f6 74 3e 8d 45 fc 50 56 ff 15 90 01 04 ff 15 90 01 04 39 45 fc 75 28 8d 85 7c ff ff ff 6a 7f 50 56 ff 15 90 01 04 8d 85 7c ff ff ff 68 90 01 04 50 ff 15 90 01 04 59 85 c0 59 90 00 } //01 00 
		$a_00_1 = {75 73 65 72 64 61 74 61 5c 63 75 72 72 65 6e 74 73 65 72 76 65 72 2e 69 6e 69 } //01 00  userdata\currentserver.ini
		$a_00_2 = {43 68 69 42 69 45 6c 65 6d 65 6e 74 43 6c 69 65 6e 74 20 57 69 6e 64 6f 77 } //01 00  ChiBiElementClient Window
		$a_01_3 = {57 72 69 74 65 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79 } //01 00  WriteProcessMemory
		$a_00_4 = {45 6c 65 6d 65 6e 74 43 6c 69 65 6e 74 2e 65 78 65 } //01 00  ElementClient.exe
		$a_01_5 = {49 6e 74 65 72 6e 65 74 52 65 61 64 46 69 6c 65 } //01 00  InternetReadFile
		$a_00_6 = {77 6f 77 2e 65 78 65 } //01 00  wow.exe
		$a_00_7 = {6c 61 73 74 47 61 6d 65 53 65 72 76 65 72 } //00 00  lastGameServer
	condition:
		any of ($a_*)
 
}