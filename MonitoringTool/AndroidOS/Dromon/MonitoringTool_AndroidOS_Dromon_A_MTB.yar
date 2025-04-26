
rule MonitoringTool_AndroidOS_Dromon_A_MTB{
	meta:
		description = "MonitoringTool:AndroidOS/Dromon.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {12 04 11 04 d8 04 [0-02] ff 23 [0-03] 05 12 [0-02] 12 [0-02] 34 [0-02] 07 00 71 10 [0-03] 00 0c 04 28 f3 39 [0-02] 07 00 44 [0-02] 07 [0-02] d8 [0-03] 01 28 f3 d8 04 [0-02] ff 44 05 07 [0-02] d0 55 80 00 d4 [0-02] 80 00 b1 65 d4 55 80 00 8e 55 50 05 [0-01] 04 28 ef } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}
rule MonitoringTool_AndroidOS_Dromon_A_MTB_2{
	meta:
		description = "MonitoringTool:AndroidOS/Dromon.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_00_0 = {53 65 6e 64 4c 6f 67 73 52 65 63 65 69 76 65 72 } //1 SendLogsReceiver
		$a_00_1 = {43 68 65 63 6b 43 61 6c 6c 4e 75 6d 62 65 72 } //1 CheckCallNumber
		$a_00_2 = {44 65 6c 43 6f 6d 61 6e 64 53 6d 73 } //1 DelComandSms
		$a_00_3 = {53 65 6e 64 4c 6f 67 46 69 6c 65 73 } //1 SendLogFiles
		$a_00_4 = {67 65 74 69 6e 66 6f 2f 54 6f 6f 6c 73 3b } //1 getinfo/Tools;
		$a_00_5 = {4c 63 6f 6d 2f 61 6d 6f 6e 2f 53 6d 73 52 65 63 65 69 76 65 72 } //1 Lcom/amon/SmsReceiver
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1) >=6
 
}