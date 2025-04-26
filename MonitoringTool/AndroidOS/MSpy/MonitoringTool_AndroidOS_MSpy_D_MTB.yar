
rule MonitoringTool_AndroidOS_MSpy_D_MTB{
	meta:
		description = "MonitoringTool:AndroidOS/MSpy.D!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {63 6f 6d 2e 6d 73 70 79 2e 6c 69 74 65 } //1 com.mspy.lite
		$a_01_1 = {4f 6e 62 6f 61 72 64 69 6e 67 54 72 61 63 6b 4e 75 6d 62 65 72 } //1 OnboardingTrackNumber
		$a_01_2 = {4f 6e 62 6f 61 72 64 69 6e 67 53 75 72 72 6f 75 6e 64 69 6e 67 73 52 65 63 6f 72 64 69 6e 67 } //1 OnboardingSurroundingsRecording
		$a_01_3 = {69 6e 6a 65 63 74 43 68 69 6c 64 4c 6f 63 61 74 69 6f 6e 53 65 6e 74 } //1 injectChildLocationSent
		$a_01_4 = {69 6e 6a 65 63 74 43 68 69 6c 64 43 6f 6e 74 61 63 74 53 65 6e 74 } //1 injectChildContactSent
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}