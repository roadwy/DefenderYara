
rule MonitoringTool_AndroidOS_Keylogger_C_MTB{
	meta:
		description = "MonitoringTool:AndroidOS/Keylogger.C!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 05 00 00 "
		
	strings :
		$a_01_0 = {74 65 6a 2e 66 6c 61 73 68 6b 65 79 6c 6f 67 67 65 72 } //1 tej.flashkeylogger
		$a_01_1 = {49 6e 70 75 74 4d 6f 6e 69 74 6f 72 53 65 72 76 69 63 65 } //1 InputMonitorService
		$a_01_2 = {67 65 74 4b 65 79 73 } //1 getKeys
		$a_01_3 = {4f 6e 4b 65 79 62 6f 61 72 64 41 63 74 69 6f 6e 4c 69 73 74 65 6e 65 72 } //1 OnKeyboardActionListener
		$a_01_4 = {67 65 74 41 63 74 69 76 65 4e 65 74 77 6f 72 6b 49 6e 66 6f } //1 getActiveNetworkInfo
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=4
 
}