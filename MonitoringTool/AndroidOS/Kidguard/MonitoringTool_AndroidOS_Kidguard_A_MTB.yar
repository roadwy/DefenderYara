
rule MonitoringTool_AndroidOS_Kidguard_A_MTB{
	meta:
		description = "MonitoringTool:AndroidOS/Kidguard.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 07 00 00 "
		
	strings :
		$a_01_0 = {4b 69 64 73 41 63 63 65 73 73 69 62 69 6c 69 74 79 53 65 72 76 69 63 65 } //1 KidsAccessibilityService
		$a_01_1 = {73 74 61 72 74 5f 6d 6f 6e 69 74 6f 72 69 6e 67 5f 6d 73 67 } //1 start_monitoring_msg
		$a_01_2 = {74 65 78 74 5f 73 6d 73 5f 70 65 72 6d 69 73 73 69 6f 6e } //1 text_sms_permission
		$a_01_3 = {67 65 74 55 73 65 72 5f 6c 6f 67 69 6e } //1 getUser_login
		$a_01_4 = {68 61 6e 64 6c 65 72 43 61 6c 6c 73 4c 6f 67 } //1 handlerCallsLog
		$a_01_5 = {69 6e 74 65 72 63 65 70 74 5f 61 63 63 65 73 73 69 62 69 6c 69 74 79 } //1 intercept_accessibility
		$a_01_6 = {53 63 72 65 65 6e 53 68 6f 74 41 63 74 69 76 69 74 79 } //1 ScreenShotActivity
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=6
 
}