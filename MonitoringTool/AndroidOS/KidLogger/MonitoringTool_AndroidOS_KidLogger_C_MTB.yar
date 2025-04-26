
rule MonitoringTool_AndroidOS_KidLogger_C_MTB{
	meta:
		description = "MonitoringTool:AndroidOS/KidLogger.C!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_00_0 = {6e 65 74 2f 73 6f 6d 65 61 70 70 31 2f 6b 65 79 62 6f 61 72 64 } //1 net/someapp1/keyboard
		$a_00_1 = {4c 61 75 6e 63 68 4b 69 64 4c 6f 67 67 65 72 } //1 LaunchKidLogger
		$a_00_2 = {73 65 6e 64 4b 65 79 } //1 sendKey
		$a_00_3 = {73 65 6e 64 54 6f 53 65 72 76 69 63 65 } //1 sendToService
		$a_00_4 = {73 65 6e 64 53 74 72 69 6e 67 } //1 sendString
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=5
 
}