
rule MonitoringTool_AndroidOS_Traca_C_MTB{
	meta:
		description = "MonitoringTool:AndroidOS/Traca.C!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {74 72 61 63 63 61 72 2e 64 62 } //1 traccar.db
		$a_01_1 = {6f 72 67 2e 74 72 61 63 63 61 72 2e 63 6c 69 65 6e 74 } //1 org.traccar.client
		$a_01_2 = {54 72 61 63 6b 69 6e 67 43 6f 6e 74 72 6f 6c 6c 65 72 } //1 TrackingController
		$a_01_3 = {73 74 6f 70 54 72 61 63 6b 69 6e 67 53 65 72 76 69 63 65 } //1 stopTrackingService
		$a_01_4 = {73 74 61 72 74 54 72 61 63 6b 69 6e 67 53 65 72 76 69 63 65 } //1 startTrackingService
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}