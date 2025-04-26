
rule MonitoringTool_AndroidOS_Itracker_A_MTB{
	meta:
		description = "MonitoringTool:AndroidOS/Itracker.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {69 54 72 61 63 6b 65 72 } //1 iTracker
		$a_01_1 = {53 74 61 72 74 55 70 55 70 64 61 74 65 72 } //1 StartUpUpdater
		$a_01_2 = {62 72 2e 63 6f 6d 2e 68 61 74 61 62 61 2e 69 74 72 61 63 6b 65 72 66 72 65 65 32 } //1 br.com.hataba.itrackerfree2
		$a_01_3 = {52 65 63 65 62 65 72 53 6d 73 } //1 ReceberSms
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}