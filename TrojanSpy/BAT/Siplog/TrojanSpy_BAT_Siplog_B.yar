
rule TrojanSpy_BAT_Siplog_B{
	meta:
		description = "TrojanSpy:BAT/Siplog.B,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 16 00 00 "
		
	strings :
		$a_01_0 = {69 53 70 79 20 4b 65 79 6c 6f 67 67 65 72 } //6 iSpy Keylogger
		$a_01_1 = {53 00 70 00 79 00 4b 00 65 00 79 00 6c 00 6f 00 67 00 67 00 65 00 72 00 } //4 SpyKeylogger
		$a_01_2 = {53 70 79 4b 65 79 6c 6f 67 67 65 72 } //2 SpyKeylogger
		$a_01_3 = {4d 65 6c 74 46 69 6c 65 } //4 MeltFile
		$a_01_4 = {52 75 6e 53 74 61 6e 64 61 72 64 42 6f 74 4b 69 6c 6c 65 72 } //3 RunStandardBotKiller
		$a_01_5 = {44 65 63 72 79 70 74 43 6f 72 65 46 54 50 50 61 73 73 77 6f 72 64 } //3 DecryptCoreFTPPassword
		$a_01_6 = {42 6f 74 6b 69 6c 6c 53 74 61 72 74 75 70 } //3 BotkillStartup
		$a_01_7 = {45 78 74 65 72 6e 61 6c 53 74 65 61 6c 65 72 73 } //2 ExternalStealers
		$a_01_8 = {46 75 63 6b 46 69 6c 65 4e 61 6d 65 } //2 FuckFileName
		$a_01_9 = {42 6f 74 6b 69 6c 6c 65 72 } //2 Botkiller
		$a_01_10 = {4b 65 79 62 6f 61 72 64 4c 6f 67 67 65 72 } //2 KeyboardLogger
		$a_01_11 = {43 6c 69 70 62 6f 61 72 64 4c 6f 67 67 65 72 } //2 ClipboardLogger
		$a_01_12 = {53 63 72 65 65 6e 73 68 6f 74 4c 6f 67 67 65 72 } //2 ScreenshotLogger
		$a_01_13 = {57 65 62 63 61 6d 4c 6f 67 67 65 72 } //2 WebcamLogger
		$a_01_14 = {41 6e 74 69 76 69 72 75 73 4b 69 6c 6c 65 72 } //2 AntivirusKiller
		$a_01_15 = {50 61 73 73 77 6f 72 64 53 74 65 61 6c 65 72 } //2 PasswordStealer
		$a_01_16 = {4d 6f 64 69 66 79 54 61 73 6b 4d 61 6e 61 67 65 72 } //2 ModifyTaskManager
		$a_01_17 = {52 65 63 6f 76 61 74 69 6f 6e 43 68 65 63 6b 43 68 61 69 6e 45 78 63 6c 75 64 65 52 6f 6f 74 } //1 RecovationCheckChainExcludeRoot
		$a_01_18 = {46 69 6c 65 5a 69 6c 6c 61 00 44 69 72 65 63 74 6f 72 79 } //1
		$a_01_19 = {4d 69 6e 65 63 72 61 66 74 00 4c 61 73 74 4c 6f 67 69 6e } //1
		$a_01_20 = {4c 61 73 74 4c 6f 67 69 6e 50 61 73 73 77 6f 72 64 } //1 LastLoginPassword
		$a_01_21 = {67 65 74 5f 4c 61 73 74 4c 6f 67 69 6e 46 69 6c 65 } //1 get_LastLoginFile
	condition:
		((#a_01_0  & 1)*6+(#a_01_1  & 1)*4+(#a_01_2  & 1)*2+(#a_01_3  & 1)*4+(#a_01_4  & 1)*3+(#a_01_5  & 1)*3+(#a_01_6  & 1)*3+(#a_01_7  & 1)*2+(#a_01_8  & 1)*2+(#a_01_9  & 1)*2+(#a_01_10  & 1)*2+(#a_01_11  & 1)*2+(#a_01_12  & 1)*2+(#a_01_13  & 1)*2+(#a_01_14  & 1)*2+(#a_01_15  & 1)*2+(#a_01_16  & 1)*2+(#a_01_17  & 1)*1+(#a_01_18  & 1)*1+(#a_01_19  & 1)*1+(#a_01_20  & 1)*1+(#a_01_21  & 1)*1) >=12
 
}