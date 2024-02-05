
rule MonitoringTool_AndroidOS_TeenSec_B_MTB{
	meta:
		description = "MonitoringTool:AndroidOS/TeenSec.B!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {73 61 76 65 4b 65 79 73 74 72 6f 6b 65 44 61 74 61 } //01 00 
		$a_01_1 = {42 72 6f 77 73 65 72 43 6f 6e 74 65 6e 74 4f 62 73 65 72 76 65 72 } //01 00 
		$a_01_2 = {63 61 6c 6c 6c 6f 67 2e 64 61 74 } //01 00 
		$a_01_3 = {73 61 76 65 49 6e 63 6f 6d 6d 69 6e 67 50 68 6f 6e 65 4e 75 6d 62 65 72 } //01 00 
		$a_01_4 = {62 6f 6f 6b 6d 61 72 6b 6c 6f 67 2e 64 61 74 } //01 00 
		$a_01_5 = {45 6d 61 69 6c 4d 65 64 69 61 52 65 63 6f 72 64 65 72 } //00 00 
	condition:
		any of ($a_*)
 
}