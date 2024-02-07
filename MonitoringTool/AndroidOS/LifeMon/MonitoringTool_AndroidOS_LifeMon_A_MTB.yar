
rule MonitoringTool_AndroidOS_LifeMon_A_MTB{
	meta:
		description = "MonitoringTool:AndroidOS/LifeMon.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_00_0 = {73 70 79 2e 6c 69 66 65 6d 6f 6e 69 74 6f 72 } //01 00  spy.lifemonitor
		$a_00_1 = {61 64 64 4c 6f 63 61 74 69 6f 6e 2e 70 68 70 } //01 00  addLocation.php
		$a_00_2 = {6f 6e 53 74 61 72 74 54 72 61 63 6b 69 6e 67 54 6f 75 63 68 } //01 00  onStartTrackingTouch
		$a_00_3 = {4c 73 70 79 2f 6c 69 66 65 6d 6f 6e 69 74 6f 72 2f 63 6f 6d 2f 74 72 61 63 6b 69 6e 67 } //00 00  Lspy/lifemonitor/com/tracking
		$a_00_4 = {5d 04 00 } //00 ae 
	condition:
		any of ($a_*)
 
}