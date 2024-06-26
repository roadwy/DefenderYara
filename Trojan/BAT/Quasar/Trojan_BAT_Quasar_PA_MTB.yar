
rule Trojan_BAT_Quasar_PA_MTB{
	meta:
		description = "Trojan:BAT/Quasar.PA!MTB,SIGNATURE_TYPE_PEHSTR,09 00 09 00 09 00 00 01 00 "
		
	strings :
		$a_01_0 = {45 4e 41 42 4c 45 4c 4f 47 47 45 52 } //01 00  ENABLELOGGER
		$a_01_1 = {48 49 44 45 4c 4f 47 44 49 52 45 43 54 4f 52 59 } //01 00  HIDELOGDIRECTORY
		$a_01_2 = {48 61 6e 64 6c 65 47 65 74 4b 65 79 6c 6f 67 67 65 72 4c 6f 67 73 } //01 00  HandleGetKeyloggerLogs
		$a_01_3 = {48 61 6e 64 6c 65 44 6f 41 73 6b 45 6c 65 76 61 74 65 } //01 00  HandleDoAskElevate
		$a_01_4 = {48 61 6e 64 6c 65 44 6f 50 72 6f 63 65 73 73 4b 69 6c 6c } //01 00  HandleDoProcessKill
		$a_01_5 = {47 65 74 53 61 76 65 64 50 61 73 73 77 6f 72 64 73 } //01 00  GetSavedPasswords
		$a_01_6 = {51 75 61 73 61 72 52 41 54 2d 6d 61 73 74 65 72 } //01 00  QuasarRAT-master
		$a_01_7 = {43 61 70 74 75 72 65 53 63 72 65 65 6e } //01 00  CaptureScreen
		$a_01_8 = {48 61 6e 64 6c 65 44 6f 55 70 6c 6f 61 64 41 6e 64 45 78 65 63 75 74 65 } //00 00  HandleDoUploadAndExecute
	condition:
		any of ($a_*)
 
}