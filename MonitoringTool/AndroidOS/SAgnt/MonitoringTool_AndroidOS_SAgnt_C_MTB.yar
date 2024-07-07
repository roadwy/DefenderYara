
rule MonitoringTool_AndroidOS_SAgnt_C_MTB{
	meta:
		description = "MonitoringTool:AndroidOS/SAgnt.C!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 05 00 00 "
		
	strings :
		$a_01_0 = {53 45 4e 54 5f 53 4d 53 5f 54 45 58 54 } //1 SENT_SMS_TEXT
		$a_00_1 = {72 75 2e 70 65 72 6d 2e 74 72 75 62 6e 69 6b 6f 76 2e 67 70 73 32 73 6d 73 } //1 ru.perm.trubnikov.gps2sms
		$a_01_2 = {41 6e 6f 74 68 65 72 4d 73 67 41 63 74 69 76 69 74 79 } //1 AnotherMsgActivity
		$a_01_3 = {73 65 6e 64 5f 72 65 63 65 69 76 65 72 5f 66 69 72 65 64 } //1 send_receiver_fired
		$a_01_4 = {72 75 70 65 72 6d 74 72 75 62 6e 69 6b 6f 76 67 70 73 32 73 6d 73 44 42 } //1 rupermtrubnikovgps2smsDB
	condition:
		((#a_01_0  & 1)*1+(#a_00_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=4
 
}