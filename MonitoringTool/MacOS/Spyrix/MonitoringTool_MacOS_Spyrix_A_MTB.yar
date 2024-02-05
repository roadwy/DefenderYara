
rule MonitoringTool_MacOS_Spyrix_A_MTB{
	meta:
		description = "MonitoringTool:MacOS/Spyrix.A!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,05 00 05 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {69 73 4d 6f 6e 69 74 6f 72 69 6e 67 4b 65 79 6c 6f 67 67 65 72 } //01 00 
		$a_01_1 = {69 73 45 6e 61 62 6c 65 41 75 74 6f 43 61 6c 6c 52 65 63 6f 72 64 65 72 } //01 00 
		$a_01_2 = {6d 6f 6e 69 74 6f 72 2f 64 61 74 61 5f 75 70 6c 6f 61 64 2e 70 68 70 } //01 00 
		$a_01_3 = {4c 69 76 65 57 65 62 43 61 6d } //01 00 
		$a_01_4 = {63 6f 6d 2e 73 70 79 72 69 78 2e 73 6b 6d } //01 00 
		$a_01_5 = {53 63 72 65 65 6e 52 65 63 6f 72 64 65 72 } //00 00 
	condition:
		any of ($a_*)
 
}
rule MonitoringTool_MacOS_Spyrix_A_MTB_2{
	meta:
		description = "MonitoringTool:MacOS/Spyrix.A!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,04 00 04 00 07 00 00 01 00 "
		
	strings :
		$a_01_0 = {63 6f 6d 2e 73 70 79 72 69 78 2e 73 6b 6d } //01 00 
		$a_01_1 = {53 70 79 72 69 78 2e 53 50 53 63 72 65 65 6e 73 68 6f 74 73 } //01 00 
		$a_01_2 = {69 73 4d 6f 6e 69 74 6f 72 69 6e 67 43 6c 69 70 62 6f 61 72 64 } //01 00 
		$a_01_3 = {73 70 79 72 69 78 2e 6e 65 74 2f 75 73 72 2f 6d 6f 6e 69 74 6f 72 2f 69 6f 72 64 65 72 2e 70 68 70 3f 69 64 3d 25 40 } //01 00 
		$a_01_4 = {53 50 4d 6f 6e 69 74 6f 72 69 6e 67 4b 65 79 62 6f 61 72 64 44 65 6c 65 67 61 74 65 } //01 00 
		$a_01_5 = {6d 6f 6e 69 74 6f 72 2f 75 70 6c 6f 61 64 33 2e 70 68 70 } //01 00 
		$a_01_6 = {73 70 79 72 69 78 2d 6b 65 79 6c 6f 67 67 65 72 2d 66 6f 72 2d 6d 61 63 2d 6d 61 6e 75 61 6c 2e 70 68 70 } //00 00 
	condition:
		any of ($a_*)
 
}