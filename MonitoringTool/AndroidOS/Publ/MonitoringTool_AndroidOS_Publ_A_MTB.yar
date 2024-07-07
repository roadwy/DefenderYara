
rule MonitoringTool_AndroidOS_Publ_A_MTB{
	meta:
		description = "MonitoringTool:AndroidOS/Publ.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {63 6f 6d 2e 70 62 6c 2e 73 65 74 74 69 6e 67 73 73 65 72 76 69 63 65 } //1 com.pbl.settingsservice
		$a_01_1 = {73 65 74 74 69 6e 67 5f 61 63 74 69 76 69 74 79 5f 74 72 61 63 6b 69 6e 67 } //1 setting_activity_tracking
		$a_01_2 = {73 65 74 74 69 6e 67 5f 67 70 73 5f 74 72 61 63 6b 69 6e 67 } //1 setting_gps_tracking
		$a_01_3 = {73 65 74 74 69 6e 67 5f 73 6d 73 5f 72 65 63 6f 72 64 65 72 } //1 setting_sms_recorder
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}