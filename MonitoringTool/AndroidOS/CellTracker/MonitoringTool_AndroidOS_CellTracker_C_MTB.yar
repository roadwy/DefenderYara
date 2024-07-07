
rule MonitoringTool_AndroidOS_CellTracker_C_MTB{
	meta:
		description = "MonitoringTool:AndroidOS/CellTracker.C!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,09 00 09 00 06 00 00 "
		
	strings :
		$a_00_0 = {74 72 61 63 6b 65 72 2e 6d 6f 62 2e 67 70 73 } //5 tracker.mob.gps
		$a_00_1 = {73 6d 73 5f 73 79 6e 63 } //1 sms_sync
		$a_00_2 = {73 63 72 65 65 6e 5f 63 61 70 74 75 72 65 } //1 screen_capture
		$a_00_3 = {6c 61 73 74 5f 73 79 6e 63 5f 63 6f 6e 74 61 63 74 73 5f 63 6f 75 6e 74 } //1 last_sync_contacts_count
		$a_00_4 = {63 61 6c 6c 5f 6c 6f 67 5f 73 79 6e 63 } //1 call_log_sync
		$a_00_5 = {73 65 6e 64 5f 61 75 64 69 6f 5f 77 69 66 69 } //1 send_audio_wifi
	condition:
		((#a_00_0  & 1)*5+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1) >=9
 
}