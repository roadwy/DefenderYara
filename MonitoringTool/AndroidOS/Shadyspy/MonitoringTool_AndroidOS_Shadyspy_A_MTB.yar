
rule MonitoringTool_AndroidOS_Shadyspy_A_MTB{
	meta:
		description = "MonitoringTool:AndroidOS/Shadyspy.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,08 00 08 00 07 00 00 "
		
	strings :
		$a_00_0 = {63 6f 6d 2e 73 68 61 64 79 73 70 79 2e 6d 6f 6e 69 74 6f 72 } //5 com.shadyspy.monitor
		$a_00_1 = {43 41 4c 4c 5f 49 4e 43 4f 4d 49 4e 47 5f 4c 4f 53 54 } //1 CALL_INCOMING_LOST
		$a_00_2 = {68 69 64 65 44 65 74 61 69 6c 73 } //1 hideDetails
		$a_00_3 = {41 43 54 49 56 49 54 59 53 48 41 44 59 53 50 59 } //1 ACTIVITYSHADYSPY
		$a_00_4 = {6e 6f 74 69 66 5f 70 68 6f 6e 65 6c 6f 67 } //1 notif_phonelog
		$a_00_5 = {73 68 61 64 79 5f 6e 6f 74 69 66 69 63 61 74 69 6f 6e 73 } //1 shady_notifications
		$a_00_6 = {73 68 61 64 79 5f 64 6f 77 6e 6c 6f 61 64 5f 63 68 61 6e 6e 65 6c } //1 shady_download_channel
	condition:
		((#a_00_0  & 1)*5+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1) >=8
 
}