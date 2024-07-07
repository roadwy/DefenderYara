
rule MonitoringTool_AndroidOS_FlexiSpy_D_MTB{
	meta:
		description = "MonitoringTool:AndroidOS/FlexiSpy.D!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {53 70 79 43 61 6c 6c 53 65 72 76 69 63 65 } //1 SpyCallService
		$a_01_1 = {4c 63 6f 6d 2f 61 6e 64 72 6f 69 64 2f 70 68 6f 6e 65 2f 73 70 63 2f 49 53 70 79 43 61 6c 6c 49 6e 74 65 72 66 61 63 65 } //1 Lcom/android/phone/spc/ISpyCallInterface
		$a_01_2 = {63 68 65 63 6b 4d 6f 6e 69 74 6f 72 69 6e 67 4e 75 6d 62 65 72 } //1 checkMonitoringNumber
		$a_01_3 = {43 61 6c 6c 42 6c 6f 63 6b 65 72 53 63 72 65 65 6e 69 6e 67 53 65 72 76 69 63 65 } //1 CallBlockerScreeningService
		$a_01_4 = {4c 63 6f 6d 2f 61 6e 64 72 6f 69 64 2f 70 68 6f 6e 65 2f 64 69 61 6c 65 72 } //1 Lcom/android/phone/dialer
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}