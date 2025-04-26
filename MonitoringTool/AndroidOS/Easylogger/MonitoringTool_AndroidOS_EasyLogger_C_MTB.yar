
rule MonitoringTool_AndroidOS_EasyLogger_C_MTB{
	meta:
		description = "MonitoringTool:AndroidOS/EasyLogger.C!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,09 00 09 00 07 00 00 "
		
	strings :
		$a_00_0 = {50 68 6f 6e 65 55 73 61 67 65 52 65 70 6f 72 74 41 63 74 69 76 69 74 79 } //2 PhoneUsageReportActivity
		$a_00_1 = {43 68 69 6c 64 4d 61 70 41 63 74 69 76 69 74 79 } //2 ChildMapActivity
		$a_00_2 = {75 6e 69 6e 73 74 61 6c 6c 46 6f 72 63 65 43 6c 6f 73 65 52 65 63 65 69 76 65 72 } //2 uninstallForceCloseReceiver
		$a_00_3 = {73 69 6d 43 68 61 6e 67 65 52 65 63 65 69 76 65 72 } //2 simChangeReceiver
		$a_00_4 = {6c 6f 53 69 6d 49 6e 66 6f 6c 6f 53 69 6d 49 6e 66 6f } //2 loSimInfoloSimInfo
		$a_00_5 = {53 65 6e 64 53 4f 53 41 6c 65 72 74 41 63 74 69 76 69 74 79 } //2 SendSOSAlertActivity
		$a_00_6 = {2f 65 61 73 79 6c 6f 67 67 65 72 } //1 /easylogger
	condition:
		((#a_00_0  & 1)*2+(#a_00_1  & 1)*2+(#a_00_2  & 1)*2+(#a_00_3  & 1)*2+(#a_00_4  & 1)*2+(#a_00_5  & 1)*2+(#a_00_6  & 1)*1) >=9
 
}