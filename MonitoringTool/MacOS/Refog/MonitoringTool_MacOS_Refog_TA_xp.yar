
rule MonitoringTool_MacOS_Refog_TA_xp{
	meta:
		description = "MonitoringTool:MacOS/Refog.TA!xp,SIGNATURE_TYPE_MACHOHSTR_EXT,05 00 05 00 07 00 00 01 00 "
		
	strings :
		$a_00_0 = {52 65 66 6f 67 20 4b 65 79 6c 6f 67 67 65 72 } //01 00 
		$a_00_1 = {4d 6f 6e 69 74 6f 72 69 6e 67 20 54 6f 6f 6c } //01 00 
		$a_00_2 = {77 77 77 2e 72 65 66 6f 67 2e 63 6f 6d 2f 6d 61 63 2f } //01 00 
		$a_02_3 = {52 65 66 6f 67 90 02 02 61 70 70 90 00 } //01 00 
		$a_00_4 = {2f 4c 69 62 72 61 72 79 2f 2e 52 65 66 6f 67 2f } //01 00 
		$a_00_5 = {4c 6f 67 2e 72 65 66 6f 67 } //01 00 
		$a_00_6 = {2f 4d 6f 6e 69 74 6f 72 2f 53 53 43 72 79 70 74 6f 2e 6d } //00 00 
		$a_00_7 = {5d 04 00 00 } //c3 ea 
	condition:
		any of ($a_*)
 
}