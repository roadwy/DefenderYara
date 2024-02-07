
rule MonitoringTool_AndroidOS_QPlus_A_MTB{
	meta:
		description = "MonitoringTool:AndroidOS/QPlus.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,03 00 03 00 04 00 00 01 00 "
		
	strings :
		$a_00_0 = {e0 05 01 04 b7 53 b0 13 dd 04 04 03 44 04 0f 04 b0 04 b7 43 b1 32 14 03 b9 79 37 9e b1 30 e1 03 02 05 3b 02 03 00 b7 73 e0 04 02 04 b7 43 b0 23 dd 04 00 03 44 04 0f 04 b0 04 b7 43 b1 31 } //01 00 
		$a_03_1 = {63 6f 6d 2f 70 6c 75 73 2f 90 02 10 2f 61 6b 90 00 } //01 00 
		$a_00_2 = {53 79 6e 63 45 78 70 6f 72 74 46 69 6c 65 73 } //01 00  SyncExportFiles
		$a_00_3 = {51 51 4d 65 73 73 61 67 65 48 69 73 74 6f 72 79 } //00 00  QQMessageHistory
	condition:
		any of ($a_*)
 
}