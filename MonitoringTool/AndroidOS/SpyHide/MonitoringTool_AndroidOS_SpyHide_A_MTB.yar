
rule MonitoringTool_AndroidOS_SpyHide_A_MTB{
	meta:
		description = "MonitoringTool:AndroidOS/SpyHide.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {63 65 6c 6c 70 68 6f 6e 65 2d 72 65 6d 6f 74 65 2d 74 72 61 63 6b 65 72 } //01 00 
		$a_01_1 = {63 6f 6d 2e 6c 32 63 65 6c 6c 74 72 61 63 6b 65 72 2e 6d 6f 62 69 6c 65 74 72 61 63 6b 65 72 } //01 00 
		$a_01_2 = {73 65 6e 64 50 68 6f 74 6f } //01 00 
		$a_01_3 = {75 70 6c 6f 61 64 41 6d 62 69 65 6e 74 } //01 00 
		$a_01_4 = {73 65 6e 64 52 65 63 6f 72 64 43 61 6c 6c 4e 65 77 } //00 00 
	condition:
		any of ($a_*)
 
}