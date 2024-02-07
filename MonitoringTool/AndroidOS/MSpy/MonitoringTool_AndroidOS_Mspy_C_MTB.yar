
rule MonitoringTool_AndroidOS_Mspy_C_MTB{
	meta:
		description = "MonitoringTool:AndroidOS/Mspy.C!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {70 65 72 66 6f 72 6d 44 61 74 61 47 61 74 68 65 72 65 72 } //01 00  performDataGatherer
		$a_01_1 = {6d 73 70 79 } //01 00  mspy
		$a_01_2 = {6d 73 70 79 6f 6e 6c 69 6e 65 } //01 00  mspyonline
		$a_01_3 = {4b 45 59 4c 4f 47 53 5f 57 49 46 49 5f 4f 4e 4c 59 } //01 00  KEYLOGS_WIFI_ONLY
		$a_01_4 = {53 4d 53 5f 57 49 46 49 5f 4f 4e 4c 59 } //01 00  SMS_WIFI_ONLY
		$a_01_5 = {4c 6f 63 61 74 69 6f 6e 47 61 74 68 65 72 69 6e 67 53 65 72 76 69 63 65 } //00 00  LocationGatheringService
	condition:
		any of ($a_*)
 
}