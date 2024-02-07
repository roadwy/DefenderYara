
rule MonitoringTool_AndroidOS_LoveTrap_B_MTB{
	meta:
		description = "MonitoringTool:AndroidOS/LoveTrap.B!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {55 6e 69 6e 73 74 61 6c 6c 41 63 74 69 76 69 74 79 } //01 00  UninstallActivity
		$a_01_1 = {70 65 6e 64 69 6e 67 70 68 6f 6e 65 73 } //01 00  pendingphones
		$a_01_2 = {4e 65 74 77 6f 72 6b 54 53 } //01 00  NetworkTS
		$a_01_3 = {55 50 4c 4f 41 44 4c 49 4d 49 54 45 44 } //01 00  UPLOADLIMITED
		$a_01_4 = {45 6d 70 74 79 5f 48 6f 6d 65 } //01 00  Empty_Home
		$a_01_5 = {69 6e 63 6f 6d 69 6e 67 5f 6e 75 6d 62 65 72 } //00 00  incoming_number
	condition:
		any of ($a_*)
 
}