
rule MonitoringTool_AndroidOS_Keylogger_B_MTB{
	meta:
		description = "MonitoringTool:AndroidOS/Keylogger.B!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {63 72 65 61 74 65 43 6f 6e 66 69 72 6d 44 65 76 69 63 65 43 72 65 64 65 6e 74 69 61 6c 49 6e 74 65 6e 74 } //01 00 
		$a_01_1 = {63 6f 6d 2f 70 78 64 77 6f 72 6b 73 2f 74 79 70 65 6b 65 65 70 65 72 } //01 00 
		$a_01_2 = {4b 65 79 67 75 61 72 64 4d 61 6e 61 67 65 72 } //01 00 
		$a_01_3 = {54 65 78 74 54 79 70 69 6e 67 41 63 74 69 76 69 74 79 } //01 00 
		$a_01_4 = {63 6f 70 79 54 6f 43 6c 69 70 62 6f 61 72 64 49 6e 70 75 74 45 76 65 6e 74 } //00 00 
	condition:
		any of ($a_*)
 
}