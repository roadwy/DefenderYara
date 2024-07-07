
rule MonitoringTool_AndroidOS_Pdaspy_A_MTB{
	meta:
		description = "MonitoringTool:AndroidOS/Pdaspy.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_00_0 = {41 70 70 6c 69 63 61 74 69 6f 6e 20 74 75 72 6e 20 69 6e 76 69 73 69 62 6c 65 20 73 70 79 20 6d 6f 64 65 20 72 69 67 68 74 20 6e 6f 77 } //1 Application turn invisible spy mode right now
		$a_00_1 = {70 64 61 73 70 79 } //1 pdaspy
		$a_00_2 = {63 61 6c 6c 4c 6f 67 67 69 6e 67 } //1 callLogging
		$a_00_3 = {72 65 61 64 4d 73 67 49 6e 62 6f 78 } //1 readMsgInbox
		$a_00_4 = {73 70 79 4c 6f 67 } //1 spyLog
		$a_01_5 = {43 61 6c 6c 53 4d 53 20 4d 6f 6e 69 74 6f 72 20 6d 65 74 68 6f 64 } //1 CallSMS Monitor method
		$a_01_6 = {73 74 61 72 74 53 4d 53 4d 6f 6e 69 74 6f 72 69 6e 67 } //1 startSMSMonitoring
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=7
 
}