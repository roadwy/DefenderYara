
rule MonitoringTool_AndroidOS_Espion_A_MTB{
	meta:
		description = "MonitoringTool:AndroidOS/Espion.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {53 63 72 65 65 6e 43 61 70 74 75 72 65 53 65 72 76 69 63 65 } //01 00  ScreenCaptureService
		$a_01_1 = {63 6f 6d 2e 65 73 70 69 6f 6e 2e 6d 6f 73 71 75 69 74 6f } //01 00  com.espion.mosquito
		$a_01_2 = {74 61 6b 65 5f 76 69 64 65 6f } //01 00  take_video
		$a_01_3 = {69 6e 66 6f 40 65 73 70 69 6f 6e 2e 6c 69 6e 6b } //01 00  info@espion.link
		$a_01_4 = {77 73 53 65 72 76 65 72 4c 69 73 74 } //00 00  wsServerList
	condition:
		any of ($a_*)
 
}