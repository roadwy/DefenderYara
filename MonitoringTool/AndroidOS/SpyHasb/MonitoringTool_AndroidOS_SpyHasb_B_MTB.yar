
rule MonitoringTool_AndroidOS_SpyHasb_B_MTB{
	meta:
		description = "MonitoringTool:AndroidOS/SpyHasb.B!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_00_0 = {6b 69 64 73 74 72 61 63 6b 65 72 2e 74 78 74 } //01 00  kidstracker.txt
		$a_00_1 = {61 70 70 6c 69 63 61 74 69 6f 6e 2f 63 61 72 2d 74 72 61 63 6b 65 72 } //01 00  application/car-tracker
		$a_00_2 = {6b 69 64 63 6c 69 65 6e 74 32 } //01 00  kidclient2
		$a_00_3 = {47 65 74 4c 69 73 74 50 6f 73 69 74 69 6f 6e 73 } //01 00  GetListPositions
		$a_00_4 = {4c 63 6f 6d 2f 63 6f 6d 70 61 6e 79 33 6c 2f 43 61 72 54 72 61 63 6b 65 72 56 69 65 77 65 72 } //00 00  Lcom/company3l/CarTrackerViewer
		$a_00_5 = {5d 04 00 00 } //cb a1 
	condition:
		any of ($a_*)
 
}