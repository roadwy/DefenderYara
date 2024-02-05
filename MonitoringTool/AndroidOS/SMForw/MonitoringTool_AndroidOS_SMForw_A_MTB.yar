
rule MonitoringTool_AndroidOS_SMForw_A_MTB{
	meta:
		description = "MonitoringTool:AndroidOS/SMForw.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_00_0 = {63 6f 6d 2f 47 72 65 65 6e 52 6f 62 6f 74 53 74 75 64 69 6f 73 2f 53 4d 53 46 6f 72 77 61 72 64 65 72 } //01 00 
		$a_00_1 = {67 72 65 65 6e 72 6f 62 6f 74 73 74 75 64 69 6f 73 2e 63 6f 6d 2f 6c 69 63 65 6e 73 69 6e 67 2f 76 61 6c 69 64 61 74 65 54 72 69 61 6c 2e 70 68 70 } //01 00 
		$a_00_2 = {50 48 4f 4e 45 5f 41 4c 49 41 53 } //01 00 
		$a_00_3 = {53 4d 53 46 6f 72 77 61 72 64 65 72 54 72 69 61 6c } //00 00 
	condition:
		any of ($a_*)
 
}