
rule MonitoringTool_AndroidOS_Keylogger_A_MTB{
	meta:
		description = "MonitoringTool:AndroidOS/Keylogger.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_00_0 = {53 68 61 72 65 20 4c 6f 67 20 46 69 6c 65 } //1 Share Log File
		$a_00_1 = {6d 6f 6e 69 74 6f 72 2e 6d 75 62 65 65 6e 2e 61 6e 64 72 6f 69 64 6b 65 79 6c 6f 67 67 65 72 } //1 monitor.mubeen.androidkeylogger
		$a_00_2 = {53 65 6e 64 54 6f 53 65 72 76 65 72 54 61 73 6b } //1 SendToServerTask
		$a_00_3 = {69 6d 61 67 65 52 65 61 64 65 72 } //1 imageReader
		$a_00_4 = {69 73 41 63 63 65 73 73 69 62 69 6c 69 74 79 53 65 74 74 69 6e 67 73 4f 6e } //1 isAccessibilitySettingsOn
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=5
 
}