
rule MonitoringTool_AndroidOS_SpyLive_B_MTB{
	meta:
		description = "MonitoringTool:AndroidOS/SpyLive.B!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {2f 6d 6f 62 69 6c 65 2f 75 70 6c 6f 61 64 2f 72 65 6d 6f 74 65 70 68 6f 74 6f } //1 /mobile/upload/remotephoto
		$a_00_1 = {6b 65 79 6c 6f 67 67 65 72 } //1 keylogger
		$a_00_2 = {48 69 64 65 41 70 70 } //1 HideApp
		$a_00_3 = {4c 63 6f 6d 2f 77 69 66 69 30 2f 61 63 74 69 76 69 74 69 65 73 } //1 Lcom/wifi0/activities
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}