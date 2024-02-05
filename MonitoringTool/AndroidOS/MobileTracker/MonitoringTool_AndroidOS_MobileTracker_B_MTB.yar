
rule MonitoringTool_AndroidOS_MobileTracker_B_MTB{
	meta:
		description = "MonitoringTool:AndroidOS/MobileTracker.B!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_00_0 = {73 6d 73 41 6c 65 72 74 4b 65 79 77 6f 72 64 2e 64 62 } //01 00 
		$a_00_1 = {53 63 72 65 65 6e 73 68 6f 6f 74 41 63 74 69 76 69 74 79 } //01 00 
		$a_00_2 = {74 72 61 63 6b 53 6f 63 69 61 6c 4e 65 74 77 6f 72 6b } //01 00 
		$a_00_3 = {6d 6d 73 2f 69 6e 73 65 72 74 4d 4d 53 56 32 2e 70 68 70 } //01 00 
		$a_00_4 = {72 65 63 6f 72 64 43 61 6c 6c 73 56 33 2f 69 6e 73 65 72 74 43 61 6c 6c 52 65 63 6f 72 64 } //01 00 
		$a_00_5 = {47 65 74 4d 65 73 73 61 67 65 57 68 61 74 73 41 70 70 } //00 00 
	condition:
		any of ($a_*)
 
}
rule MonitoringTool_AndroidOS_MobileTracker_B_MTB_2{
	meta:
		description = "MonitoringTool:AndroidOS/MobileTracker.B!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,07 00 07 00 07 00 00 01 00 "
		
	strings :
		$a_01_0 = {63 6f 6d 2f 76 69 6f 6e 69 6b 61 2f 6d 6f 62 69 76 65 6d 65 6e 74 2f 75 69 2f 63 68 69 6c 64 6d 61 6e 61 67 65 6d 65 6e 74 2f 70 68 6f 6e 65 6f 70 74 69 6f 6e 73 } //01 00 
		$a_01_1 = {63 68 6d 6f 64 20 25 64 20 25 73 } //01 00 
		$a_01_2 = {6d 6f 62 69 76 65 6d 65 6e 74 41 67 65 6e 74 55 70 67 72 61 64 65 2e 61 70 6b } //01 00 
		$a_01_3 = {4e 6f 74 69 66 69 63 61 74 69 6f 6e 4c 69 73 74 65 6e 65 72 53 65 72 76 69 63 65 } //01 00 
		$a_01_4 = {69 73 41 64 6d 69 6e 41 63 74 69 76 65 } //01 00 
		$a_01_5 = {72 65 73 65 74 50 61 73 73 77 6f 72 64 } //01 00 
		$a_01_6 = {6c 6f 63 6b 4e 6f 77 } //00 00 
	condition:
		any of ($a_*)
 
}