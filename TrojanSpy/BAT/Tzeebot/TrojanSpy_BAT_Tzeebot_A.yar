
rule TrojanSpy_BAT_Tzeebot_A{
	meta:
		description = "TrojanSpy:BAT/Tzeebot.A,SIGNATURE_TYPE_PEHSTR_EXT,1d 00 1d 00 0c 00 00 02 00 "
		
	strings :
		$a_01_0 = {43 6c 65 61 76 65 72 2e 4e 65 74 } //01 00  Cleaver.Net
		$a_01_1 = {47 65 74 4d 61 63 68 69 6e 49 50 4c 69 73 74 } //01 00  GetMachinIPList
		$a_01_2 = {45 6d 61 69 6c 53 65 6e 64 50 65 72 69 6f 64 } //01 00  EmailSendPeriod
		$a_01_3 = {43 72 65 61 74 65 4e 65 77 4b 65 79 4c 6f 67 46 69 6c 65 } //01 00  CreateNewKeyLogFile
		$a_01_4 = {43 68 65 63 6b 41 6e 64 53 61 76 65 4c 6f 67 46 69 6c 65 } //01 00  CheckAndSaveLogFile
		$a_01_5 = {55 73 65 72 41 63 74 69 76 69 74 79 48 6f 6f 6b 5f 4f 6e 41 63 74 69 76 65 57 69 6e 64 6f 77 43 68 61 6e 67 65 64 } //01 00  UserActivityHook_OnActiveWindowChanged
		$a_01_6 = {4b 69 6c 6c 54 68 69 73 41 67 65 6e 74 } //01 00  KillThisAgent
		$a_01_7 = {53 61 76 65 43 6f 6e 66 69 67 41 6e 64 52 65 6c 6f 61 64 } //01 00  SaveConfigAndReload
		$a_01_8 = {50 72 6f 63 65 73 73 55 70 64 61 74 65 43 6f 6d 6d 61 6e 64 73 } //03 00  ProcessUpdateCommands
		$a_03_9 = {06 17 58 0a 90 0a 40 00 07 7e 90 01 02 00 04 7e 90 01 02 00 04 90 02 02 6f 90 01 02 00 0a 6f 90 01 02 00 0a 8c 90 01 01 00 00 01 28 90 01 01 00 00 0a 0b 90 00 } //0a 00 
		$a_01_10 = {54 5a 42 5f 53 74 61 72 74 75 70 } //0a 00  TZB_Startup
		$a_01_11 = {54 69 6e 79 5a 42 6f 74 } //00 00  TinyZBot
		$a_00_12 = {80 10 00 00 a2 e6 28 0c 2a 61 bd e8 19 4c 36 e4 c2 01 00 80 5d 04 } //00 00 
	condition:
		any of ($a_*)
 
}