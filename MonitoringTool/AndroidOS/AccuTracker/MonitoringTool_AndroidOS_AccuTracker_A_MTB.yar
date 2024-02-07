
rule MonitoringTool_AndroidOS_AccuTracker_A_MTB{
	meta:
		description = "MonitoringTool:AndroidOS/AccuTracker.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 05 00 00 02 00 "
		
	strings :
		$a_00_0 = {4c 63 6f 6d 2f 61 63 63 75 74 72 61 63 6b 69 6e 67 2f 41 63 63 75 54 72 61 63 6b 69 6e 67 } //01 00  Lcom/accutracking/AccuTracking
		$a_00_1 = {54 72 61 63 6b 69 6e 67 42 72 6f 61 64 63 61 73 74 52 65 63 65 69 76 65 72 } //01 00  TrackingBroadcastReceiver
		$a_00_2 = {53 65 6e 64 69 6e 67 20 64 61 74 61 } //01 00  Sending data
		$a_00_3 = {67 61 74 65 77 61 79 2e 61 63 63 75 74 72 61 63 6b 69 6e 67 2e 75 73 } //01 00  gateway.accutracking.us
		$a_00_4 = {62 50 77 64 50 72 6f 74 65 63 74 65 64 } //00 00  bPwdProtected
		$a_00_5 = {5d 04 00 00 } //00 f6 
	condition:
		any of ($a_*)
 
}