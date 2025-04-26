
rule MonitoringTool_AndroidOS_KidLogger_A_MTB{
	meta:
		description = "MonitoringTool:AndroidOS/KidLogger.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_00_0 = {6c 6f 67 43 61 6c 6c 73 } //1 logCalls
		$a_00_1 = {67 65 74 4b 65 79 73 74 72 6f 6b 65 } //1 getKeystroke
		$a_00_2 = {75 70 6c 6f 61 64 4b 65 79 } //1 uploadKey
		$a_00_3 = {4b 69 64 4c 6f 63 4c 69 73 74 65 6e 65 72 } //1 KidLocListener
		$a_00_4 = {6e 65 74 2e 6b 69 64 6c 6f 67 67 65 72 } //1 net.kidlogger
		$a_00_5 = {6c 6f 67 67 65 72 6b 65 79 62 6f 61 72 64 } //1 loggerkeyboard
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1) >=6
 
}