
rule MonitoringTool_AndroidOS_Dnotua_B_MTB{
	meta:
		description = "MonitoringTool:AndroidOS/Dnotua.B!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {53 63 72 65 65 6e 43 68 61 6e 63 65 64 52 65 63 65 69 76 65 72 } //1 ScreenChancedReceiver
		$a_01_1 = {63 6f 6d 2f 73 70 61 70 70 6d 5f 6d 6f 6e 64 6f 77 2f 61 6c 61 72 6d 2f 43 68 69 6c 64 4c 6f 63 61 74 6f 72 } //1 com/spappm_mondow/alarm/ChildLocator
		$a_01_2 = {72 65 6d 6f 74 65 5f 77 69 70 65 } //1 remote_wipe
		$a_01_3 = {54 72 61 63 6b 4c 6f 63 61 74 69 6f 6e } //1 TrackLocation
		$a_01_4 = {4e 6f 74 69 66 69 63 61 74 69 6f 6e 4c 69 73 74 65 6e 65 72 } //1 NotificationListener
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}