
rule MonitoringTool_AndroidOS_Phonesher_B_MTB{
	meta:
		description = "MonitoringTool:AndroidOS/Phonesher.B!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,18 00 18 00 08 00 00 01 00 "
		
	strings :
		$a_01_0 = {50 68 6f 6e 65 20 57 69 70 65 } //01 00  Phone Wipe
		$a_01_1 = {53 49 4d 20 49 6e 66 6f } //0a 00  SIM Info
		$a_01_2 = {70 68 6f 6e 65 73 68 65 72 } //01 00  phonesher
		$a_01_3 = {4b 45 59 5f 49 53 5f 53 54 4f 50 5f 4d 4f 4e 49 54 4f 52 49 4e 47 } //01 00  KEY_IS_STOP_MONITORING
		$a_01_4 = {67 65 74 50 72 65 70 61 72 65 64 43 6f 6e 74 61 63 74 4c 6f 67 73 } //01 00  getPreparedContactLogs
		$a_01_5 = {42 72 6f 77 73 65 72 20 52 65 63 6f 72 64 73 } //01 00  Browser Records
		$a_01_6 = {55 50 4c 4f 41 44 5f 41 4c 4c 5f 4c 4f 47 53 } //0a 00  UPLOAD_ALL_LOGS
		$a_00_7 = {63 6f 6d 2e 72 65 74 69 6e 61 2e 70 73 2e 76 32 } //00 00  com.retina.ps.v2
	condition:
		any of ($a_*)
 
}