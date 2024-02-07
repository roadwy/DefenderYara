
rule Adware_BAT_Tracker_A{
	meta:
		description = "Adware:BAT/Tracker.A,SIGNATURE_TYPE_PEHSTR,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {62 75 79 69 6e 67 5f 74 72 61 63 6b 5f 69 64 } //01 00  buying_track_id
		$a_01_1 = {73 61 6c 65 73 5f 74 72 61 63 6b 5f 69 64 } //01 00  sales_track_id
		$a_01_2 = {73 61 6c 65 73 5f 63 61 6d 70 61 69 67 6e 5f 74 61 72 67 65 74 5f 69 64 } //01 00  sales_campaign_target_id
		$a_01_3 = {41 00 6e 00 61 00 6c 00 79 00 73 00 69 00 73 00 44 00 61 00 74 00 61 00 2e 00 65 00 78 00 65 00 } //01 00  AnalysisData.exe
		$a_01_4 = {61 00 73 00 70 00 6e 00 65 00 74 00 5f 00 77 00 70 00 2e 00 65 00 78 00 65 00 } //00 00  aspnet_wp.exe
	condition:
		any of ($a_*)
 
}