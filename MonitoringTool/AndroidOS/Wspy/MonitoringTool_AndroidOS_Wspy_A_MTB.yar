
rule MonitoringTool_AndroidOS_Wspy_A_MTB{
	meta:
		description = "MonitoringTool:AndroidOS/Wspy.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {77 65 62 68 69 73 74 6f 72 79 } //1 webhistory
		$a_01_1 = {6b 65 79 6c 6f 67 67 65 72 } //1 keylogger
		$a_01_2 = {53 63 72 65 65 6e 4c 6f 63 6b 55 6e 6c 6f 63 6b } //1 ScreenLockUnlock
		$a_01_3 = {2f 6d 6f 62 69 6c 65 2f 75 70 6c 6f 61 64 2f 72 65 6d 6f 74 65 70 68 6f 74 6f } //1 /mobile/upload/remotephoto
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}