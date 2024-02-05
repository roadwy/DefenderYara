
rule MonitoringTool_AndroidOS_TeenSec_A_MTB{
	meta:
		description = "MonitoringTool:AndroidOS/TeenSec.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {73 63 72 65 65 6e 73 68 61 72 65 74 6f 62 72 6f 77 73 65 72 } //01 00 
		$a_01_1 = {61 70 70 55 73 61 67 65 48 69 73 74 6f 72 79 46 6f 72 } //01 00 
		$a_01_2 = {45 6d 61 69 6c 41 63 63 6f 75 6e 74 52 65 6d 6f 76 65 72 } //01 00 
		$a_01_3 = {63 70 2e 73 65 63 75 72 65 74 65 65 6e 2e 63 6f 6d 2f 62 6c 6f 63 6b 2f } //01 00 
		$a_01_4 = {53 63 72 65 65 6e 4d 6f 6e 69 74 6f 72 69 6e 67 53 65 72 76 69 63 65 } //01 00 
		$a_01_5 = {43 61 6c 6c 50 61 72 72 65 6e 74 41 63 74 69 76 69 74 79 } //00 00 
	condition:
		any of ($a_*)
 
}