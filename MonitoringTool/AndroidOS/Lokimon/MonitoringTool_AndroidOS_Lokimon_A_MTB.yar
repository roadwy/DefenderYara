
rule MonitoringTool_AndroidOS_Lokimon_A_MTB{
	meta:
		description = "MonitoringTool:AndroidOS/Lokimon.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {4c 6f 6b 69 41 63 74 69 76 69 74 79 } //01 00  LokiActivity
		$a_01_1 = {68 69 64 65 5f 61 70 70 5f 69 63 6f 6e } //01 00  hide_app_icon
		$a_01_2 = {63 68 61 72 67 65 5f 73 6d 73 5f 73 65 6e 64 } //01 00  charge_sms_send
		$a_00_3 = {63 6f 6d 2e 6d 6f 62 69 6c 65 2e 6c 6f 6b 69 } //01 00  com.mobile.loki
		$a_01_4 = {73 65 72 76 69 63 65 5f 63 6f 6d 6d 61 6e 64 5f 73 6d 73 } //00 00  service_command_sms
	condition:
		any of ($a_*)
 
}