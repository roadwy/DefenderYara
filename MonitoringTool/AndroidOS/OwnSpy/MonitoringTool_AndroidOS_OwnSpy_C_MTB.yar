
rule MonitoringTool_AndroidOS_OwnSpy_C_MTB{
	meta:
		description = "MonitoringTool:AndroidOS/OwnSpy.C!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {2f 6f 77 6e 73 70 79 2e 70 68 70 } //01 00 
		$a_01_1 = {63 6f 6d 2e 6f 77 6e 73 70 79 2e 61 6e 64 72 6f 69 64 2e 41 70 70 } //01 00 
		$a_01_2 = {35 33 39 37 34 39 37 34 39 39 35 33 30 35 32 39 32 35 33 32 6f 77 6e 73 70 79 38 33 38 32 37 32 34 39 32 39 34 30 30 33 34 39 34 32 33 30 34 31 } //01 00 
		$a_01_3 = {6f 6e 55 6e 69 76 65 72 73 61 6c 52 65 63 65 69 76 65 } //00 00 
	condition:
		any of ($a_*)
 
}