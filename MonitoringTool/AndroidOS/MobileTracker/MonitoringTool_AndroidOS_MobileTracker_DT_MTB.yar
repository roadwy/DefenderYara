
rule MonitoringTool_AndroidOS_MobileTracker_DT_MTB{
	meta:
		description = "MonitoringTool:AndroidOS/MobileTracker.DT!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {74 72 61 63 6b 53 6e 61 70 63 68 61 74 4e 6f 52 6f 6f 74 } //1 trackSnapchatNoRoot
		$a_01_1 = {74 72 61 63 6b 59 6f 75 74 75 62 65 48 69 73 74 6f 72 79 } //1 trackYoutubeHistory
		$a_01_2 = {74 72 61 63 6b 4c 6f 63 47 50 53 } //1 trackLocGPS
		$a_01_3 = {6d 79 61 70 70 6d 6f 62 69 6c 65 32 30 31 39 } //1 myappmobile2019
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}