
rule MonitoringTool_AndroidOS_Spyoo_C_MTB{
	meta:
		description = "MonitoringTool:AndroidOS/Spyoo.C!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_00_0 = {41 6e 64 72 6f 69 64 4d 6f 6e 69 74 6f 72 41 70 70 6c 69 63 61 74 69 6f 6e } //1 AndroidMonitorApplication
		$a_00_1 = {4f 75 74 47 6f 69 6e 67 43 61 6c 6c 52 65 63 65 69 76 65 72 } //1 OutGoingCallReceiver
		$a_00_2 = {6c 61 73 74 5f 77 68 61 74 73 61 70 70 5f 64 61 74 65 } //1 last_whatsapp_date
		$a_00_3 = {63 6f 6d 2f 69 73 70 79 6f 6f 2f 63 6f 6d 6d 6f 6e 2f 6d 6f 6e 69 74 6f 72 2f 53 70 79 41 70 70 } //1 com/ispyoo/common/monitor/SpyApp
		$a_00_4 = {69 73 5f 72 65 63 6f 72 64 5f 63 61 6c 6c 5f 61 63 74 69 76 65 } //1 is_record_call_active
		$a_00_5 = {2f 6c 6f 67 5f 63 61 6c 6c 5f 72 65 63 6f 72 64 69 6e 67 2e 61 73 70 78 } //1 /log_call_recording.aspx
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1) >=6
 
}