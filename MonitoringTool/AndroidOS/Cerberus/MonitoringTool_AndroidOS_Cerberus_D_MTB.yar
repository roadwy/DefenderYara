
rule MonitoringTool_AndroidOS_Cerberus_D_MTB{
	meta:
		description = "MonitoringTool:AndroidOS/Cerberus.D!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {50 68 6f 6e 65 43 61 6c 6c 57 6f 72 6b 65 72 } //1 PhoneCallWorker
		$a_01_1 = {53 6e 61 70 50 69 63 53 65 72 76 69 63 65 } //1 SnapPicService
		$a_01_2 = {53 4f 53 53 65 6e 64 57 6f 72 6b 65 72 } //1 SOSSendWorker
		$a_01_3 = {63 6f 6d 2e 6c 73 64 72 6f 69 64 2e 63 65 72 62 65 72 75 73 2e 70 65 72 73 6f 6e 61 } //1 com.lsdroid.cerberus.persona
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}