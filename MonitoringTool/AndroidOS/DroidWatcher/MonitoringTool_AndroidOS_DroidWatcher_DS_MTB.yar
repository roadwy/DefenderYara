
rule MonitoringTool_AndroidOS_DroidWatcher_DS_MTB{
	meta:
		description = "MonitoringTool:AndroidOS/DroidWatcher.DS!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 06 00 00 01 00 "
		
	strings :
		$a_00_0 = {74 69 6d 65 73 5f 63 6f 6e 74 61 63 74 65 64 } //01 00  times_contacted
		$a_00_1 = {6c 61 73 74 5f 63 6f 6e 74 61 63 74 5f 74 69 6d 65 } //01 00  last_contact_time
		$a_00_2 = {2f 73 64 63 61 72 64 2f 73 70 79 69 65 72 2f 4c 6f 67 73 2f } //01 00  /sdcard/spyier/Logs/
		$a_00_3 = {73 74 61 72 74 57 61 74 63 68 69 6e 67 2e 2e 2e 2e 2e 2e } //01 00  startWatching......
		$a_00_4 = {75 70 6c 6f 61 64 4d 6f 62 69 6c 65 49 6e 66 6f } //01 00  uploadMobileInfo
		$a_00_5 = {46 69 6c 65 4d 6f 6e 69 74 6f 72 20 68 61 73 20 61 6c 72 65 61 64 79 20 73 74 61 72 74 65 64 21 } //00 00  FileMonitor has already started!
	condition:
		any of ($a_*)
 
}