
rule TrojanSpy_BAT_KeyLogger_BS{
	meta:
		description = "TrojanSpy:BAT/KeyLogger.BS,SIGNATURE_TYPE_PEHSTR,0a 00 0a 00 0c 00 00 01 00 "
		
	strings :
		$a_01_0 = {4c 69 76 65 4b 65 79 4c 6f 67 } //01 00  LiveKeyLog
		$a_01_1 = {47 65 74 4b 65 79 4c 6f 67 } //01 00  GetKeyLog
		$a_01_2 = {47 65 74 50 61 73 73 77 6f 72 64 73 } //01 00  GetPasswords
		$a_01_3 = {47 65 74 53 63 72 65 65 6e } //01 00  GetScreen
		$a_01_4 = {53 74 61 72 74 43 68 61 74 } //01 00  StartChat
		$a_01_5 = {53 74 61 72 74 43 4d 44 } //01 00  StartCMD
		$a_01_6 = {53 74 61 72 74 53 74 72 65 73 73 } //01 00  StartStress
		$a_01_7 = {53 74 61 72 74 57 65 62 63 61 6d } //01 00  StartWebcam
		$a_01_8 = {53 74 61 72 74 44 6f 77 6e 6c 6f 61 64 } //01 00  StartDownload
		$a_01_9 = {53 74 61 72 74 55 70 6c 6f 61 64 } //01 00  StartUpload
		$a_01_10 = {44 69 73 61 62 6c 65 43 4d 44 } //01 00  DisableCMD
		$a_01_11 = {44 69 73 61 62 6c 65 54 61 73 6b 4d 47 52 } //00 00  DisableTaskMGR
		$a_01_12 = {00 5d 04 00 00 31 } //67 03 
	condition:
		any of ($a_*)
 
}