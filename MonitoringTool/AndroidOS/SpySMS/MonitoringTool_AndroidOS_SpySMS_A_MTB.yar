
rule MonitoringTool_AndroidOS_SpySMS_A_MTB{
	meta:
		description = "MonitoringTool:AndroidOS/SpySMS.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {63 6f 6e 74 61 63 74 73 52 65 61 64 } //01 00 
		$a_01_1 = {6e 65 74 2e 73 6f 66 74 62 72 61 69 6e 2e 73 6d 73 64 69 76 65 72 74 6f 72 } //01 00 
		$a_01_2 = {73 6d 73 53 65 6e 64 } //01 00 
		$a_01_3 = {63 6f 6e 74 65 6e 74 3a 2f 2f 73 6d 73 2f 63 6f 6e 76 65 72 73 61 74 69 6f 6e 73 2f } //01 00 
		$a_01_4 = {44 69 76 65 72 74 6f 72 52 65 63 65 69 76 65 72 } //00 00 
	condition:
		any of ($a_*)
 
}