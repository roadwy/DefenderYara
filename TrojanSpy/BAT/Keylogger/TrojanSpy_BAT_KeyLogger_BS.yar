
rule TrojanSpy_BAT_KeyLogger_BS{
	meta:
		description = "TrojanSpy:BAT/KeyLogger.BS,SIGNATURE_TYPE_PEHSTR,0a 00 0a 00 0c 00 00 "
		
	strings :
		$a_01_0 = {4c 69 76 65 4b 65 79 4c 6f 67 } //1 LiveKeyLog
		$a_01_1 = {47 65 74 4b 65 79 4c 6f 67 } //1 GetKeyLog
		$a_01_2 = {47 65 74 50 61 73 73 77 6f 72 64 73 } //1 GetPasswords
		$a_01_3 = {47 65 74 53 63 72 65 65 6e } //1 GetScreen
		$a_01_4 = {53 74 61 72 74 43 68 61 74 } //1 StartChat
		$a_01_5 = {53 74 61 72 74 43 4d 44 } //1 StartCMD
		$a_01_6 = {53 74 61 72 74 53 74 72 65 73 73 } //1 StartStress
		$a_01_7 = {53 74 61 72 74 57 65 62 63 61 6d } //1 StartWebcam
		$a_01_8 = {53 74 61 72 74 44 6f 77 6e 6c 6f 61 64 } //1 StartDownload
		$a_01_9 = {53 74 61 72 74 55 70 6c 6f 61 64 } //1 StartUpload
		$a_01_10 = {44 69 73 61 62 6c 65 43 4d 44 } //1 DisableCMD
		$a_01_11 = {44 69 73 61 62 6c 65 54 61 73 6b 4d 47 52 } //1 DisableTaskMGR
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1+(#a_01_10  & 1)*1+(#a_01_11  & 1)*1) >=10
 
}