
rule MonitoringTool_AndroidOS_TTSpy_A_MTB{
	meta:
		description = "MonitoringTool:AndroidOS/TTSpy.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {6c 6f 61 64 41 6e 64 53 61 76 65 44 65 76 69 63 65 49 6e 66 6f } //1 loadAndSaveDeviceInfo
		$a_00_1 = {63 6f 6d 2e 62 61 63 6b 75 70 2e 74 74 } //1 com.backup.tt
		$a_01_2 = {74 74 73 70 79 } //1 ttspy
		$a_01_3 = {63 72 65 61 74 65 53 63 72 65 65 6e 43 61 70 74 75 72 65 49 6e 74 65 6e 74 } //1 createScreenCaptureIntent
		$a_01_4 = {2f 62 72 6f 77 73 65 72 2f 68 69 73 74 6f 72 79 } //1 /browser/history
	condition:
		((#a_01_0  & 1)*1+(#a_00_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}