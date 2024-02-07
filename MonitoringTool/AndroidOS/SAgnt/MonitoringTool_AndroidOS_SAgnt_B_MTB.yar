
rule MonitoringTool_AndroidOS_SAgnt_B_MTB{
	meta:
		description = "MonitoringTool:AndroidOS/SAgnt.B!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 07 00 00 01 00 "
		
	strings :
		$a_01_0 = {63 61 6c 6c 5f 6e 75 6d 62 65 72 3d } //01 00  call_number=
		$a_01_1 = {73 74 61 72 74 55 70 6c 6f 61 64 20 } //01 00  startUpload 
		$a_01_2 = {75 70 64 61 74 65 54 72 61 63 6b 65 72 54 61 62 6c 65 } //01 00  updateTrackerTable
		$a_01_3 = {74 72 61 63 6b 5f 6c 6f 63 61 74 69 6f 6e } //01 00  track_location
		$a_01_4 = {67 65 74 43 68 72 6f 6d 65 42 72 6f 77 73 65 72 48 69 73 74 } //01 00  getChromeBrowserHist
		$a_01_5 = {67 65 74 53 4d 53 48 69 73 74 6f 72 79 } //01 00  getSMSHistory
		$a_01_6 = {64 65 6c 4f 6c 64 44 61 74 61 54 6f 48 69 73 74 6f 72 79 50 68 6f 68 65 } //00 00  delOldDataToHistoryPhohe
	condition:
		any of ($a_*)
 
}