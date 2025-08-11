
rule Trojan_AndroidOS_Mamont_K_MTB{
	meta:
		description = "Trojan:AndroidOS/Mamont.K!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {73 65 6e 64 41 70 70 73 4c 69 73 74 54 6f 54 65 6c 65 67 72 61 6d } //1 sendAppsListToTelegram
		$a_01_1 = {4c 63 6f 6d 2f 65 78 61 6d 70 6c 65 2f 74 65 73 74 72 61 74 2f 53 6d 73 52 65 63 65 69 76 65 72 } //1 Lcom/example/testrat/SmsReceiver
		$a_01_2 = {73 65 6e 64 4e 6f 74 69 66 69 63 61 74 69 6f 6e 54 6f 54 65 6c 65 67 72 61 6d } //1 sendNotificationToTelegram
		$a_01_3 = {73 65 6e 64 54 65 6c 65 67 72 61 6d 4d 65 73 73 61 67 65 } //1 sendTelegramMessage
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}