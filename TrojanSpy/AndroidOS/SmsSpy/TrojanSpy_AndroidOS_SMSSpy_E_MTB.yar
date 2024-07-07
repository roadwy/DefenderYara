
rule TrojanSpy_AndroidOS_SMSSpy_E_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/SMSSpy.E!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_00_0 = {67 65 74 49 6e 63 6f 6d 69 6e 67 4d 65 73 73 61 67 65 } //1 getIncomingMessage
		$a_00_1 = {2f 73 6d 73 2e 70 68 70 } //1 /sms.php
		$a_00_2 = {73 65 6e 64 65 72 4e 6f } //1 senderNo
		$a_00_3 = {69 72 2f 69 72 61 6e 2f 70 61 72 64 61 6b 68 74 2f 53 4d 53 42 72 6f 61 64 63 61 73 74 52 65 63 65 69 76 65 72 } //1 ir/iran/pardakht/SMSBroadcastReceiver
		$a_00_4 = {64 65 6c 65 74 65 43 68 61 74 } //1 deleteChat
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=5
 
}