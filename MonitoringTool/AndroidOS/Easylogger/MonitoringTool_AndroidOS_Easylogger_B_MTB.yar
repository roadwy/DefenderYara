
rule MonitoringTool_AndroidOS_Easylogger_B_MTB{
	meta:
		description = "MonitoringTool:AndroidOS/Easylogger.B!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 06 00 00 "
		
	strings :
		$a_01_0 = {61 70 70 2f 45 61 73 79 4c 6f 67 67 65 72 } //2 app/EasyLogger
		$a_00_1 = {68 74 74 70 3a 2f 2f 6c 6f 67 67 65 72 2e 6d 6f 62 69 } //1 http://logger.mobi
		$a_01_2 = {48 69 64 65 41 70 70 } //1 HideApp
		$a_01_3 = {49 6e 73 65 72 74 4c 6f 67 48 69 73 74 6f 72 79 4d 61 6e 61 67 65 72 } //1 InsertLogHistoryManager
		$a_01_4 = {43 61 6c 6c 4c 6f 67 } //1 CallLog
		$a_01_5 = {45 61 73 79 4c 6f 67 67 65 72 4c 6f 67 2e 64 62 } //1 EasyLoggerLog.db
	condition:
		((#a_01_0  & 1)*2+(#a_00_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=5
 
}