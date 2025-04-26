
rule MonitoringTool_AndroidOS_MobiStealth_A_MTB{
	meta:
		description = "MonitoringTool:AndroidOS/MobiStealth.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {6d 6f 62 69 73 74 65 61 6c 74 68 } //1 mobistealth
		$a_01_1 = {73 6d 73 6c 6f 67 2e 64 61 74 } //1 smslog.dat
		$a_01_2 = {53 74 65 61 6c 74 68 42 61 63 6b 55 70 44 61 74 61 } //1 StealthBackUpData
		$a_01_3 = {45 6d 61 69 6c 43 61 6c 6c 52 65 63 6f 72 64 69 6e 67 53 65 72 76 69 63 65 } //1 EmailCallRecordingService
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}