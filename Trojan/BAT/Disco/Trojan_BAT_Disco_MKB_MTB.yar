
rule Trojan_BAT_Disco_MKB_MTB{
	meta:
		description = "Trojan:BAT/Disco.MKB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,23 00 23 00 05 00 00 "
		
	strings :
		$a_81_0 = {5b 2a 5d 20 53 74 65 61 6c 69 6e 67 20 54 65 6c 65 67 72 61 6d 20 73 65 73 73 69 6f 6e 73 2e 2e 2e } //15 [*] Stealing Telegram sessions...
		$a_81_1 = {41 6b 61 63 68 75 20 53 74 65 61 6c 65 72 20 2d 20 44 69 73 63 6f 72 64 20 46 6f 75 6e 64 } //10 Akachu Stealer - Discord Found
		$a_01_2 = {44 69 73 63 6f 72 64 53 74 65 61 6c 65 72 } //5 DiscordStealer
		$a_01_3 = {53 74 65 61 6c 53 74 65 61 6d } //3 StealSteam
		$a_01_4 = {53 74 65 61 6c 54 65 6c 65 67 72 61 6d } //2 StealTelegram
	condition:
		((#a_81_0  & 1)*15+(#a_81_1  & 1)*10+(#a_01_2  & 1)*5+(#a_01_3  & 1)*3+(#a_01_4  & 1)*2) >=35
 
}