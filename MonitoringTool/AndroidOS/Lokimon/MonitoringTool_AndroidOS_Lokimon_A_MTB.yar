
rule MonitoringTool_AndroidOS_Lokimon_A_MTB{
	meta:
		description = "MonitoringTool:AndroidOS/Lokimon.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {4c 6f 6b 69 41 63 74 69 76 69 74 79 } //1 LokiActivity
		$a_01_1 = {68 69 64 65 5f 61 70 70 5f 69 63 6f 6e } //1 hide_app_icon
		$a_01_2 = {63 68 61 72 67 65 5f 73 6d 73 5f 73 65 6e 64 } //1 charge_sms_send
		$a_00_3 = {63 6f 6d 2e 6d 6f 62 69 6c 65 2e 6c 6f 6b 69 } //1 com.mobile.loki
		$a_01_4 = {73 65 72 76 69 63 65 5f 63 6f 6d 6d 61 6e 64 5f 73 6d 73 } //1 service_command_sms
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_00_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}