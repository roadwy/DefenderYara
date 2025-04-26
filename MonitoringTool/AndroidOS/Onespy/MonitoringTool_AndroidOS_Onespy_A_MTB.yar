
rule MonitoringTool_AndroidOS_Onespy_A_MTB{
	meta:
		description = "MonitoringTool:AndroidOS/Onespy.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_00_0 = {50 68 6f 6e 65 43 61 6c 6c 53 70 79 4c 69 73 74 65 6e 65 72 } //1 PhoneCallSpyListener
		$a_00_1 = {41 64 64 20 63 6f 6e 74 65 6e 74 20 6f 62 73 65 72 76 65 72 20 66 6f 72 20 69 6e 63 6f 6d 69 6e 67 20 73 6d 73 } //1 Add content observer for incoming sms
		$a_01_2 = {50 55 4c 4c 52 45 51 55 45 53 54 5f 73 6b 79 70 65 6c 6f 67 } //1 PULLREQUEST_skypelog
		$a_00_3 = {73 65 6e 64 41 6c 6c 43 68 61 74 4d 65 73 73 61 67 65 73 } //1 sendAllChatMessages
		$a_00_4 = {73 65 6e 64 54 77 69 74 74 65 72 48 69 73 74 6f 72 79 } //1 sendTwitterHistory
		$a_00_5 = {74 6f 6f 20 65 61 72 6c 79 20 74 6f 20 73 65 6e 64 20 67 6d 61 69 6c 20 64 62 } //1 too early to send gmail db
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_01_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1) >=6
 
}