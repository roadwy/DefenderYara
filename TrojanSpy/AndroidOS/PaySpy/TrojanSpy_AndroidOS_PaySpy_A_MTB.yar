
rule TrojanSpy_AndroidOS_PaySpy_A_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/PaySpy.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {70 61 79 6e 6f 74 69 63 65 } //1 paynotice
		$a_00_1 = {43 75 73 74 6f 6d 4e 6f 74 69 66 69 63 61 74 69 6f 6e 4c 69 73 74 65 6e 65 72 53 65 72 76 69 63 65 } //1 CustomNotificationListenerService
		$a_00_2 = {4c 6f 6e 67 52 75 6e 6e 69 6e 67 53 65 72 76 69 63 65 } //1 LongRunningService
		$a_00_3 = {4c 63 6f 6d 2f 74 65 6e 63 65 6e 74 2f 6d 6f 62 69 6c 65 71 71 2f 53 6d 73 52 65 63 65 69 76 65 72 } //1 Lcom/tencent/mobileqq/SmsReceiver
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}