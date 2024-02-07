
rule MonitoringTool_AndroidOS_Spyset_A_MTB{
	meta:
		description = "MonitoringTool:AndroidOS/Spyset.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_00_0 = {53 70 79 4d 61 69 6e 56 69 65 77 } //01 00  SpyMainView
		$a_00_1 = {72 65 6d 6f 76 65 55 70 64 61 74 65 73 } //01 00  removeUpdates
		$a_00_2 = {53 70 79 53 65 72 76 69 63 65 24 4d 79 4c 6f 63 61 74 69 6f 6e 4c 69 73 74 65 6e 65 72 } //01 00  SpyService$MyLocationListener
		$a_00_3 = {53 70 79 53 65 72 76 69 63 65 } //01 00  SpyService
		$a_00_4 = {53 70 79 53 61 74 50 72 65 66 73 } //00 00  SpySatPrefs
		$a_00_5 = {5d 04 00 00 } //30 91 
	condition:
		any of ($a_*)
 
}