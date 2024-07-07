
rule MonitoringTool_AndroidOS_TrackView_D_MTB{
	meta:
		description = "MonitoringTool:AndroidOS/TrackView.D!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {63 6f 6d 2f 68 6f 6d 65 73 61 66 65 2f 63 61 6c 6c } //1 com/homesafe/call
		$a_01_1 = {4c 6f 63 61 74 69 6f 6e 48 69 73 74 6f 72 79 53 65 72 76 69 63 65 } //1 LocationHistoryService
		$a_01_2 = {74 72 61 63 6b 76 69 65 77 3a 2f 70 61 79 6d 65 6e 74 5f 72 65 73 75 6c 74 3f } //1 trackview:/payment_result?
		$a_01_3 = {4c 6f 63 61 74 69 6f 6e 52 65 63 6f 72 64 44 61 74 61 } //1 LocationRecordData
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}