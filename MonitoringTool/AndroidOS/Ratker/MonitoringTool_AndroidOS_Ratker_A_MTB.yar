
rule MonitoringTool_AndroidOS_Ratker_A_MTB{
	meta:
		description = "MonitoringTool:AndroidOS/Ratker.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {53 4d 53 44 75 6d 6d 79 43 6f 6d 70 6f 73 65 } //1 SMSDummyCompose
		$a_01_1 = {43 61 6c 6c 52 65 63 6f 72 64 65 72 53 65 72 76 69 63 65 } //1 CallRecorderService
		$a_01_2 = {63 6f 6d 2f 74 72 61 63 65 72 2f 61 63 74 69 76 69 74 79 } //1 com/tracer/activity
		$a_01_3 = {53 4d 53 43 6f 6d 6d 61 6e 64 53 65 72 76 69 63 65 } //1 SMSCommandService
		$a_01_4 = {52 65 6d 6f 74 65 43 6f 6d 6d 61 6e 64 73 52 65 63 65 69 76 65 72 } //1 RemoteCommandsReceiver
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}