
rule MonitoringTool_AndroidOS_SAgnt_D_MTB{
	meta:
		description = "MonitoringTool:AndroidOS/SAgnt.D!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_00_0 = {54 72 61 63 6b 65 64 20 43 65 6c 6c 20 50 68 6f 6e 65 73 } //01 00 
		$a_01_1 = {41 70 70 20 6d 6f 6e 69 74 6f 72 69 6e 67 } //01 00 
		$a_01_2 = {6d 6f 6e 69 74 6f 72 65 64 20 63 65 6c 6c 20 70 68 6f 6e 65 73 } //01 00 
		$a_00_3 = {4c 63 6f 6d 2f 61 6e 64 72 6f 69 64 61 70 6c 69 63 61 74 69 76 6f 73 2f 70 68 6f 6e 65 74 72 61 63 6b 65 72 62 79 6e 75 6d 62 65 72 } //00 00 
	condition:
		any of ($a_*)
 
}