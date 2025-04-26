
rule MonitoringTool_AndroidOS_TalkLog_C_MTB{
	meta:
		description = "MonitoringTool:AndroidOS/TalkLog.C!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 07 00 00 "
		
	strings :
		$a_01_0 = {74 61 6c 6b 6c 6f 67 2e 6e 65 74 } //1 talklog.net
		$a_01_1 = {64 65 6c 65 74 65 4f 6c 64 41 70 70 } //1 deleteOldApp
		$a_01_2 = {43 6f 6c 6c 65 63 74 42 72 6f 77 73 65 72 53 65 72 76 69 63 65 } //1 CollectBrowserService
		$a_01_3 = {43 6f 6c 6c 65 63 74 43 61 6c 6c 53 65 72 76 69 63 65 } //1 CollectCallService
		$a_01_4 = {43 6f 6c 6c 65 63 74 4d 6d 73 53 65 72 76 69 63 65 } //1 CollectMmsService
		$a_01_5 = {43 6f 6c 6c 65 63 74 50 68 6f 74 6f 53 65 72 76 69 63 65 } //1 CollectPhotoService
		$a_01_6 = {43 6f 6c 6c 65 63 74 53 6d 73 53 65 72 76 69 63 65 } //1 CollectSmsService
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=6
 
}