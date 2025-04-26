
rule MonitoringTool_AndroidOS_MobTool_B_MTB{
	meta:
		description = "MonitoringTool:AndroidOS/MobTool.B!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_00_0 = {77 69 70 65 44 61 74 61 } //1 wipeData
		$a_00_1 = {73 6d 73 5f 63 6d 64 5f 73 65 72 76 69 63 65 5f 72 65 73 74 61 72 74 69 6e 67 } //1 sms_cmd_service_restarting
		$a_00_2 = {72 65 63 6f 72 64 5f 63 61 6c 6c 73 } //1 record_calls
		$a_00_3 = {74 72 61 63 6b 5f 67 65 6f } //1 track_geo
		$a_00_4 = {75 70 6c 6f 61 64 5f 68 69 73 74 6f 72 79 } //1 upload_history
		$a_00_5 = {6f 75 74 5f 73 6d 73 } //1 out_sms
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1) >=6
 
}