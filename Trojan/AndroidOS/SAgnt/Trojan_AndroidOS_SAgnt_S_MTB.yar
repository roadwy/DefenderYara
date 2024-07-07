
rule Trojan_AndroidOS_SAgnt_S_MTB{
	meta:
		description = "Trojan:AndroidOS/SAgnt.S!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 05 00 00 "
		
	strings :
		$a_01_0 = {42 6f 74 41 70 70 41 63 74 69 76 69 74 79 } //1 BotAppActivity
		$a_01_1 = {73 65 6e 64 53 4d 53 } //1 sendSMS
		$a_01_2 = {63 6f 6d 2f 61 70 70 2f 62 6f 74 } //1 com/app/bot
		$a_01_3 = {53 6d 73 52 65 63 65 69 76 65 72 } //1 SmsReceiver
		$a_01_4 = {62 6f 74 2f 53 65 72 76 69 63 65 43 6f 6e 74 72 6f 6c 6c 65 72 } //1 bot/ServiceController
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=4
 
}