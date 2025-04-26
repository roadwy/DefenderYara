
rule MonitoringTool_AndroidOS_MobileTracker_DS_MTB{
	meta:
		description = "MonitoringTool:AndroidOS/MobileTracker.DS!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_00_0 = {74 72 61 63 6b 53 4d 53 } //1 trackSMS
		$a_00_1 = {73 63 72 65 65 6e 63 61 70 74 75 72 65 45 6e 61 62 6c 65 64 } //1 screencaptureEnabled
		$a_00_2 = {73 69 74 65 2f 69 6e 73 65 72 74 53 69 74 65 48 69 73 74 6f 72 79 2e 70 68 70 } //1 site/insertSiteHistory.php
		$a_00_3 = {72 65 6d 6f 74 65 43 6f 6e 74 72 6f 6c 2f 73 65 74 4c 6f 67 2e 70 68 70 } //1 remoteControl/setLog.php
		$a_00_4 = {63 6f 6e 66 69 67 52 65 63 6f 72 64 43 61 6c 6c 73 } //1 configRecordCalls
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=5
 
}