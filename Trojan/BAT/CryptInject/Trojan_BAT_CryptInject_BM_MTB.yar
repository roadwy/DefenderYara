
rule Trojan_BAT_CryptInject_BM_MTB{
	meta:
		description = "Trojan:BAT/CryptInject.BM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_00_0 = {5c 00 64 00 69 00 73 00 63 00 6f 00 72 00 64 00 5c 00 4c 00 6f 00 63 00 61 00 6c 00 20 00 53 00 74 00 6f 00 72 00 61 00 67 00 65 00 5c 00 6c 00 65 00 76 00 65 00 6c 00 64 00 62 00 5c 00 } //01 00  \discord\Local Storage\leveldb\
		$a_01_1 = {44 00 69 00 73 00 63 00 6f 00 72 00 64 00 48 00 61 00 78 00 78 00 20 00 54 00 6f 00 6b 00 65 00 6e 00 20 00 47 00 72 00 61 00 62 00 62 00 65 00 72 00 } //01 00  DiscordHaxx Token Grabber
		$a_01_2 = {68 00 74 00 74 00 70 00 73 00 3a 00 2f 00 2f 00 6d 00 65 00 64 00 69 00 61 00 2e 00 64 00 69 00 73 00 63 00 6f 00 72 00 64 00 61 00 70 00 70 00 2e 00 6e 00 65 00 74 00 2f 00 61 00 74 00 74 00 61 00 63 00 68 00 6d 00 65 00 6e 00 74 00 73 00 } //01 00  https://media.discordapp.net/attachments
		$a_01_3 = {68 00 74 00 74 00 70 00 73 00 3a 00 2f 00 2f 00 77 00 74 00 66 00 69 00 73 00 6d 00 79 00 69 00 70 00 2e 00 63 00 6f 00 6d 00 2f 00 74 00 65 00 78 00 74 00 } //00 00  https://wtfismyip.com/text
	condition:
		any of ($a_*)
 
}