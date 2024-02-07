
rule MonitoringTool_AndroidOS_Spyzie_A_MTB{
	meta:
		description = "MonitoringTool:AndroidOS/Spyzie.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {6c 61 73 74 5f 62 61 63 6b 75 70 5f 74 69 6d 65 } //01 00  last_backup_time
		$a_01_1 = {74 74 70 73 3a 2f 2f 6d 79 2e 73 70 79 7a 69 65 2e 63 6f 6d 2f 61 70 70 2f 73 70 79 7a 69 65 2e 6a 73 6f 6e } //01 00  ttps://my.spyzie.com/app/spyzie.json
		$a_01_2 = {53 70 79 7a 69 65 50 69 63 74 75 72 65 2f } //01 00  SpyziePicture/
		$a_01_3 = {53 70 79 7a 69 65 5f 53 74 61 72 74 } //01 00  Spyzie_Start
		$a_01_4 = {6c 61 73 74 4d 6f 6e 69 74 6f 72 44 65 76 69 63 65 } //00 00  lastMonitorDevice
	condition:
		any of ($a_*)
 
}