
rule MonitoringTool_AndroidOS_DroidWatcher_B_MTB{
	meta:
		description = "MonitoringTool:AndroidOS/DroidWatcher.B!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {4c 63 6f 6d 2f 64 65 6c 65 6d 65 6e 74 6f 2f 73 65 72 76 69 63 65 73 } //01 00 
		$a_01_1 = {63 6c 69 70 62 6f 61 72 64 2d 68 69 73 74 6f 72 79 2e 74 78 74 } //01 00 
		$a_01_2 = {73 65 6e 64 43 61 6c 6c 4c 6f 67 } //01 00 
		$a_01_3 = {73 65 6e 64 53 6d 73 4c 6f 67 } //01 00 
		$a_01_4 = {63 6f 70 79 42 72 6f 77 73 65 72 54 6f 44 57 44 42 } //00 00 
	condition:
		any of ($a_*)
 
}