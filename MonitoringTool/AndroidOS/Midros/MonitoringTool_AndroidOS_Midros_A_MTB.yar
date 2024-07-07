
rule MonitoringTool_AndroidOS_Midros_A_MTB{
	meta:
		description = "MonitoringTool:AndroidOS/Midros.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_00_0 = {4d 6f 6e 69 74 6f 72 53 65 72 76 69 63 65 } //1 MonitorService
		$a_00_1 = {73 74 61 72 74 41 70 70 43 68 65 63 6b 65 72 } //1 startAppChecker
		$a_00_2 = {73 6d 73 53 65 72 76 69 63 65 } //1 smsService
		$a_00_3 = {67 65 74 43 61 70 74 75 72 65 50 68 6f 74 6f } //1 getCapturePhoto
		$a_00_4 = {4c 63 6f 6d 2f 6d 79 2f 73 70 79 2f 61 70 70 2f 72 65 63 65 69 76 65 72 2f 43 61 6c 6c 73 52 65 63 65 69 76 65 72 } //1 Lcom/my/spy/app/receiver/CallsReceiver
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=5
 
}
rule MonitoringTool_AndroidOS_Midros_A_MTB_2{
	meta:
		description = "MonitoringTool:AndroidOS/Midros.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 07 00 00 "
		
	strings :
		$a_00_0 = {6b 65 79 4c 6f 67 67 65 72 } //1 keyLogger
		$a_00_1 = {2f 61 75 64 69 6f 43 61 6c 6c 73 } //1 /audioCalls
		$a_00_2 = {73 65 6e 64 46 69 6c 65 43 61 6c 6c } //1 sendFileCall
		$a_00_3 = {49 6e 74 65 72 61 63 74 6f 72 53 6d 73 } //1 InteractorSms
		$a_00_4 = {49 6e 74 65 72 61 63 74 6f 72 43 61 6c 6c 73 } //1 InteractorCalls
		$a_00_5 = {67 65 74 53 68 6f 77 4f 72 48 69 64 65 41 70 70 } //1 getShowOrHideApp
		$a_00_6 = {67 65 74 4c 6f 63 6b 50 69 6e } //1 getLockPin
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1) >=6
 
}