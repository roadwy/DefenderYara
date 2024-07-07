
rule MonitoringTool_AndroidOS_CellTracker_A_MTB{
	meta:
		description = "MonitoringTool:AndroidOS/CellTracker.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 06 00 00 "
		
	strings :
		$a_01_0 = {77 77 77 2e 74 72 61 63 6b 6d 79 70 68 6f 6e 65 73 2e 63 6f 6d } //1 www.trackmyphones.com
		$a_01_1 = {73 74 72 65 65 74 6c 65 6e 73 } //1 streetlens
		$a_01_2 = {67 63 6d 63 61 6c 6c 73 6d 73 74 72 61 63 6b 65 72 } //1 gcmcallsmstracker
		$a_03_3 = {72 65 6d 6f 74 65 90 02 02 63 65 6c 6c 90 02 02 74 72 61 63 6b 65 72 90 00 } //1
		$a_01_4 = {74 72 61 63 6b 79 61 70 70 73 } //1 trackyapps
		$a_01_5 = {43 65 6c 6c 54 72 61 63 6b 65 72 41 63 74 69 76 69 74 79 } //1 CellTrackerActivity
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_03_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=4
 
}
rule MonitoringTool_AndroidOS_CellTracker_A_MTB_2{
	meta:
		description = "MonitoringTool:AndroidOS/CellTracker.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,0f 00 0f 00 08 00 00 "
		
	strings :
		$a_01_0 = {43 41 4c 4c 44 41 54 41 } //1 CALLDATA
		$a_00_1 = {63 6f 6d 2e 6a 79 6f 74 69 6e 2e 63 74 } //10 com.jyotin.ct
		$a_01_2 = {69 73 5f 61 70 70 5f 68 69 64 65 } //1 is_app_hide
		$a_01_3 = {73 6d 73 5f 73 79 6e 63 } //1 sms_sync
		$a_01_4 = {63 61 6c 6c 5f 6c 6f 67 5f 73 79 6e 63 } //1 call_log_sync
		$a_01_5 = {73 63 72 65 65 6e 5f 63 61 70 74 75 72 65 } //1 screen_capture
		$a_01_6 = {73 65 6e 64 5f 61 75 64 69 6f 5f 77 69 66 69 } //1 send_audio_wifi
		$a_01_7 = {6c 61 73 74 5f 73 79 6e 63 5f 63 6f 6e 74 61 63 74 73 5f 63 6f 75 6e 74 } //1 last_sync_contacts_count
	condition:
		((#a_01_0  & 1)*1+(#a_00_1  & 1)*10+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1) >=15
 
}