
rule Trojan_AndroidOS_Mamont_N_MTB{
	meta:
		description = "Trojan:AndroidOS/Mamont.N!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {73 65 6e 64 50 6f 73 74 52 65 71 75 65 73 74 53 6d 73 41 70 70 } //1 sendPostRequestSmsApp
		$a_01_1 = {73 65 6e 74 53 70 65 63 69 61 6c 53 65 6e 64 65 72 73 54 6f 64 61 79 } //1 sentSpecialSendersToday
		$a_01_2 = {73 74 61 72 74 43 68 65 63 6b 69 6e 67 46 6f 72 4e 65 77 53 4d 53 } //1 startCheckingForNewSMS
		$a_01_3 = {64 65 6c 69 76 65 72 79 2d 74 6f 70 2e 72 75 2f 73 65 6e 64 2d 73 6d 73 } //1 delivery-top.ru/send-sms
		$a_01_4 = {70 61 72 73 65 41 6e 64 53 65 6e 64 53 70 65 63 69 61 6c 53 4d 53 } //1 parseAndSendSpecialSMS
		$a_01_5 = {77 73 73 3a 2f 2f 64 65 6c 69 76 65 72 79 2d 74 6f 70 2e 72 75 2f 73 6f 63 6b 65 74 } //1 wss://delivery-top.ru/socket
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}