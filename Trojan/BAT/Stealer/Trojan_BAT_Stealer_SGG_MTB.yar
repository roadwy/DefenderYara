
rule Trojan_BAT_Stealer_SGG_MTB{
	meta:
		description = "Trojan:BAT/Stealer.SGG!MTB,SIGNATURE_TYPE_PEHSTR,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {54 65 6c 65 67 72 61 6d 53 74 65 61 6c 65 72 2e 65 78 65 } //01 00  TelegramStealer.exe
		$a_01_1 = {4b 69 6c 6c 54 65 6c 65 67 72 61 6d } //01 00  KillTelegram
		$a_01_2 = {61 00 70 00 69 00 2e 00 74 00 65 00 6c 00 65 00 67 00 72 00 61 00 6d 00 2e 00 6f 00 72 00 67 00 2f 00 62 00 6f 00 74 00 } //01 00  api.telegram.org/bot
		$a_01_3 = {2f 00 2f 00 74 00 2e 00 6d 00 65 00 2f 00 53 00 61 00 6d 00 73 00 45 00 78 00 70 00 6c 00 6f 00 69 00 74 00 } //00 00  //t.me/SamsExploit
	condition:
		any of ($a_*)
 
}