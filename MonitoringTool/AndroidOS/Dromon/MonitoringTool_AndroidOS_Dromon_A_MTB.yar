
rule MonitoringTool_AndroidOS_Dromon_A_MTB{
	meta:
		description = "MonitoringTool:AndroidOS/Dromon.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_03_0 = {12 04 11 04 d8 04 90 02 02 ff 23 90 02 03 05 12 90 02 02 12 90 02 02 34 90 02 02 07 00 71 10 90 02 03 00 0c 04 28 f3 39 90 02 02 07 00 44 90 02 02 07 90 02 02 d8 90 02 03 01 28 f3 d8 04 90 02 02 ff 44 05 07 90 02 02 d0 55 80 00 d4 90 02 02 80 00 b1 65 d4 55 80 00 8e 55 50 05 90 02 01 04 28 ef 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule MonitoringTool_AndroidOS_Dromon_A_MTB_2{
	meta:
		description = "MonitoringTool:AndroidOS/Dromon.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_00_0 = {53 65 6e 64 4c 6f 67 73 52 65 63 65 69 76 65 72 } //01 00  SendLogsReceiver
		$a_00_1 = {43 68 65 63 6b 43 61 6c 6c 4e 75 6d 62 65 72 } //01 00  CheckCallNumber
		$a_00_2 = {44 65 6c 43 6f 6d 61 6e 64 53 6d 73 } //01 00  DelComandSms
		$a_00_3 = {53 65 6e 64 4c 6f 67 46 69 6c 65 73 } //01 00  SendLogFiles
		$a_00_4 = {67 65 74 69 6e 66 6f 2f 54 6f 6f 6c 73 3b } //01 00  getinfo/Tools;
		$a_00_5 = {4c 63 6f 6d 2f 61 6d 6f 6e 2f 53 6d 73 52 65 63 65 69 76 65 72 } //00 00  Lcom/amon/SmsReceiver
	condition:
		any of ($a_*)
 
}