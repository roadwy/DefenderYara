
rule MonitoringTool_AndroidOS_Spymob_A_MTB{
	meta:
		description = "MonitoringTool:AndroidOS/Spymob.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 04 00 00 "
		
	strings :
		$a_00_0 = {73 70 79 32 6d 6f 62 69 6c 65 2e 64 62 } //2 spy2mobile.db
		$a_00_1 = {6d 6f 62 69 6c 65 73 70 79 } //1 mobilespy
		$a_00_2 = {54 72 61 63 6b 65 72 53 65 72 76 69 63 65 } //1 TrackerService
		$a_00_3 = {73 6d 73 5f 68 69 73 74 6f 72 79 } //1 sms_history
	condition:
		((#a_00_0  & 1)*2+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=5
 
}
rule MonitoringTool_AndroidOS_Spymob_A_MTB_2{
	meta:
		description = "MonitoringTool:AndroidOS/Spymob.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {63 00 29 00 38 00 18 00 22 00 6c 00 70 10 3f 01 00 00 1a 02 d9 00 6e 20 43 01 20 00 0c 00 6e 20 43 01 30 00 0c 00 6e 10 44 01 00 00 0c 00 71 20 4a 00 40 00 63 00 21 00 } //1
		$a_01_1 = {64 65 6c 65 74 65 41 70 70 } //1 deleteApp
		$a_01_2 = {67 65 74 50 61 63 6b 61 67 65 4e 61 6d 65 } //1 getPackageName
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}