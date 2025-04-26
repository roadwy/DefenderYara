
rule MonitoringTool_AndroidOS_FunSpy_A_MTB{
	meta:
		description = "MonitoringTool:AndroidOS/FunSpy.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_00_0 = {61 63 63 65 73 73 69 62 69 6c 69 74 79 69 6e 66 6f } //1 accessibilityinfo
		$a_00_1 = {6b 65 79 6c 6f 67 67 65 72 74 6f } //1 keyloggerto
		$a_00_2 = {46 6f 72 53 4d 53 43 6f 6d 6d 61 6e 64 43 6f 64 65 73 } //1 ForSMSCommandCodes
		$a_00_3 = {43 61 6c 6c 52 65 63 6f 72 64 69 6e 67 41 6e 64 43 6f 6e 74 72 6f 6c 53 65 72 76 69 63 65 } //1 CallRecordingAndControlService
		$a_00_4 = {63 68 65 63 6b 5f 73 63 72 65 65 6e 73 68 6f 74 } //1 check_screenshot
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=5
 
}