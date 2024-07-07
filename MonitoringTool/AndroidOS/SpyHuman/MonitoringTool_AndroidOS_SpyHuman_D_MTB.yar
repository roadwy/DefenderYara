
rule MonitoringTool_AndroidOS_SpyHuman_D_MTB{
	meta:
		description = "MonitoringTool:AndroidOS/SpyHuman.D!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 05 00 00 "
		
	strings :
		$a_01_0 = {6e 6f 74 69 66 69 63 61 74 69 6f 6e 74 72 61 63 6b } //1 notificationtrack
		$a_01_1 = {63 6f 6d 2e 61 6e 74 69 74 68 65 66 74 73 65 72 76 69 63 65 } //1 com.antitheftservice
		$a_01_2 = {57 65 6c 63 6f 6d 65 5f 73 70 79 68 75 6d 61 6e } //1 Welcome_spyhuman
		$a_01_3 = {57 61 74 63 68 44 6f 67 53 65 72 76 69 63 65 52 65 63 65 69 76 65 72 } //1 WatchDogServiceReceiver
		$a_01_4 = {6d 6f 6e 69 74 6f 72 69 6e 67 5f 6f 70 61 74 69 6f 6e } //1 monitoring_opation
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=4
 
}