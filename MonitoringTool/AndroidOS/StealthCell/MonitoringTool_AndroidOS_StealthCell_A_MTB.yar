
rule MonitoringTool_AndroidOS_StealthCell_A_MTB{
	meta:
		description = "MonitoringTool:AndroidOS/StealthCell.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,09 00 09 00 06 00 00 01 00 "
		
	strings :
		$a_00_0 = {67 65 74 43 61 6c 6c 53 75 6d 6d 61 72 79 41 6e 64 55 70 64 61 74 65 56 69 65 77 } //01 00  getCallSummaryAndUpdateView
		$a_00_1 = {73 6d 73 6f 62 73 65 72 76 65 72 } //01 00  smsobserver
		$a_00_2 = {77 69 70 65 64 61 74 61 } //05 00  wipedata
		$a_00_3 = {6d 6f 62 69 73 74 65 61 6c 74 68 } //01 00  mobistealth
		$a_00_4 = {43 41 4c 4c 53 5f 44 61 74 61 } //01 00  CALLS_Data
		$a_00_5 = {68 69 64 65 61 70 70 } //00 00  hideapp
	condition:
		any of ($a_*)
 
}