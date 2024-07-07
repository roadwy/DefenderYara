
rule MonitoringTool_AndroidOS_NickyRCP_A_MTB{
	meta:
		description = "MonitoringTool:AndroidOS/NickyRCP.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_00_0 = {72 65 6d 6f 74 65 2d 63 6f 6e 74 72 6f 6c 2d 70 68 6f 6e 65 } //1 remote-control-phone
		$a_00_1 = {73 65 6e 64 53 4d 53 57 61 69 74 } //1 sendSMSWait
		$a_00_2 = {67 65 74 4c 61 73 74 4b 6e 6f 77 6e 4c 6f 63 61 74 69 6f 6e } //1 getLastKnownLocation
		$a_00_3 = {66 61 6b 65 43 61 6c 6c 65 72 52 65 71 75 65 73 74 } //1 fakeCallerRequest
		$a_00_4 = {73 6d 73 6d 61 74 63 68 65 72 } //1 smsmatcher
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=5
 
}