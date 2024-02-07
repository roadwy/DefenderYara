
rule MonitoringTool_AndroidOS_Spyzie_DS_MTB{
	meta:
		description = "MonitoringTool:AndroidOS/Spyzie.DS!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_00_0 = {75 70 6c 6f 61 64 6d 6f 6e 69 74 6f 72 62 72 6f 77 73 65 72 } //01 00  uploadmonitorbrowser
		$a_00_1 = {75 70 6c 6f 61 64 56 69 64 65 6f 3a 20 73 74 61 72 74 } //01 00  uploadVideo: start
		$a_00_2 = {73 70 5f 77 69 66 69 5f 6c 6f 67 67 65 72 } //01 00  sp_wifi_logger
		$a_00_3 = {73 70 79 70 68 6f 6e 65 5f 64 61 74 61 } //01 00  spyphone_data
		$a_00_4 = {7a 69 70 55 70 6c 6f 61 64 44 62 20 73 74 61 72 74 20 75 70 6c 6f 61 64 } //00 00  zipUploadDb start upload
	condition:
		any of ($a_*)
 
}