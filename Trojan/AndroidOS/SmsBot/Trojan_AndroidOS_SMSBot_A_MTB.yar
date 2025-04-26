
rule Trojan_AndroidOS_SMSBot_A_MTB{
	meta:
		description = "Trojan:AndroidOS/SMSBot.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_00_0 = {73 61 76 65 64 5f 61 75 74 68 5f 73 6d 73 5f 74 65 78 74 } //1 saved_auth_sms_text
		$a_00_1 = {53 6d 73 4c 6f 67 } //1 SmsLog
		$a_00_2 = {42 4f 54 5f 49 44 } //1 BOT_ID
		$a_00_3 = {2f 62 6f 74 2e 70 68 70 } //1 /bot.php
		$a_00_4 = {73 61 76 65 64 5f 73 6d 73 5f 6e 75 6d 62 65 72 } //1 saved_sms_number
		$a_00_5 = {42 6f 74 53 65 72 76 69 63 65 } //1 BotService
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1) >=6
 
}