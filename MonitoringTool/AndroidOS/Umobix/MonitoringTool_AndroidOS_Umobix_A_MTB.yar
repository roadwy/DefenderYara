
rule MonitoringTool_AndroidOS_Umobix_A_MTB{
	meta:
		description = "MonitoringTool:AndroidOS/Umobix.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_00_0 = {41 70 70 41 63 74 69 76 69 74 79 4d 6f 6e 69 74 6f 72 } //1 AppActivityMonitor
		$a_00_1 = {4b 65 79 6c 6f 67 67 65 72 53 63 61 6e 6e 65 72 } //1 KeyloggerScanner
		$a_00_2 = {73 63 72 65 65 6e 5f 72 65 61 64 65 72 } //1 screen_reader
		$a_00_3 = {41 70 70 42 6c 6f 63 6b 65 72 41 63 74 69 76 69 74 79 } //1 AppBlockerActivity
		$a_00_4 = {62 72 6f 77 73 65 72 5f 68 69 73 74 6f 72 79 } //1 browser_history
		$a_00_5 = {45 4e 41 42 4c 45 5f 44 49 53 50 4c 41 59 5f 52 45 43 4f 52 44 45 52 } //1 ENABLE_DISPLAY_RECORDER
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1) >=6
 
}