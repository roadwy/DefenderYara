
rule MonitoringTool_AndroidOS_Hovermon_A_MTB{
	meta:
		description = "MonitoringTool:AndroidOS/Hovermon.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {53 4d 53 53 43 52 45 45 4e 53 48 4f 54 53 } //1 SMSSCREENSHOTS
		$a_00_1 = {4d 6f 6e 69 74 6f 72 48 49 6e 73 74 61 6c 6c 2e 61 70 6b } //1 MonitorHInstall.apk
		$a_00_2 = {61 70 69 2e 73 6e 6f 6f 70 7a 61 2e 63 6f 6d } //1 api.snoopza.com
		$a_00_3 = {6d 6f 6e 69 74 6f 72 65 64 5f 6c 6f 67 73 } //1 monitored_logs
		$a_01_4 = {57 45 42 53 43 52 45 45 4e 53 48 4f 54 53 } //1 WEBSCREENSHOTS
		$a_00_5 = {68 69 64 65 5f 6c 61 75 6e 63 68 65 72 } //1 hide_launcher
	condition:
		((#a_01_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_01_4  & 1)*1+(#a_00_5  & 1)*1) >=6
 
}