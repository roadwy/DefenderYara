
rule TrojanSpy_AndroidOS_SmsThief_BO_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/SmsThief.BO!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {63 6f 6d 2f 63 6f 6d 70 6c 61 69 6e 74 6d 61 6e 61 67 65 72 } //1 com/complaintmanager
		$a_01_1 = {46 6f 72 77 61 72 64 4d 65 73 73 61 67 65 4f 6e 4d 6f 62 69 6c 65 } //1 ForwardMessageOnMobile
		$a_01_2 = {73 65 6e 64 4d 65 73 73 61 67 65 54 6f 53 65 72 76 65 72 } //1 sendMessageToServer
		$a_01_3 = {63 61 6c 6c 41 70 69 54 6f 53 65 6e 64 53 6d 73 4f 6e 53 65 72 76 65 72 45 76 65 72 79 31 35 4d 69 6e } //1 callApiToSendSmsOnServerEvery15Min
		$a_01_4 = {53 6d 73 50 72 6f 63 65 73 73 53 65 72 76 69 63 65 } //1 SmsProcessService
		$a_01_5 = {61 64 64 61 6c 6c 6d 65 73 73 65 67 65 } //1 addallmessege
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}