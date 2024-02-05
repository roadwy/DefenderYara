
rule MonitoringTool_AndroidOS_XoloSale_A_MTB{
	meta:
		description = "MonitoringTool:AndroidOS/XoloSale.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {6d 49 73 53 69 6d 43 61 72 64 30 4c 69 73 74 65 6e 6e 69 6e 67 } //01 00 
		$a_01_1 = {4b 45 59 5f 52 45 47 49 53 54 5f 4d 53 47 5f 53 48 4f 57 49 4e 47 } //01 00 
		$a_01_2 = {54 72 61 63 6b 65 72 41 6c 61 72 6d 53 65 72 76 69 63 65 } //01 00 
		$a_01_3 = {53 6d 73 53 65 6e 64 69 6e 67 43 6c 61 73 73 } //00 00 
	condition:
		any of ($a_*)
 
}