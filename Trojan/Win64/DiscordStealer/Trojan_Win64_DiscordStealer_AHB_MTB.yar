
rule Trojan_Win64_DiscordStealer_AHB_MTB{
	meta:
		description = "Trojan:Win64/DiscordStealer.AHB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 06 00 00 "
		
	strings :
		$a_03_0 = {0f 57 c0 0f 11 45 ?? 4c 89 ?? ?? 4c 89 ?? ?? 0f 10 00 0f 11 45 ?? 0f 10 48 10 0f 11 4d ?? 4c 89 ?? 10 48 c7 40 18 0f 00 00 00 c6 00 00 48 8b 54 24 ?? 48 83 fa 0f } //5
		$a_01_1 = {5c 4c 6f 63 61 6c 20 53 74 6f 72 61 67 65 5c 6c 65 76 65 6c 64 62 } //1 \Local Storage\leveldb
		$a_01_2 = {77 65 62 68 6f 6f 6b 2e 73 69 74 65 } //1 webhook.site
		$a_01_3 = {5c 64 69 73 63 6f 72 64 63 61 6e 61 72 79 } //1 \discordcanary
		$a_01_4 = {5c 4c 69 67 68 74 63 6f 72 64 } //1 \Lightcord
		$a_01_5 = {5c 64 69 73 63 6f 72 64 70 74 62 } //1 \discordptb
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=10
 
}