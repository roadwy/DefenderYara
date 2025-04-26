
rule Trojan_BAT_Disstl_AV_MTB{
	meta:
		description = "Trojan:BAT/Disstl.AV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,15 00 15 00 07 00 00 "
		
	strings :
		$a_80_0 = {61 7a 75 6c 61 5f 6c 6f 67 67 65 72 } //azula_logger  3
		$a_80_1 = {4b 69 6c 6c 44 69 73 63 6f 72 64 } //KillDiscord  3
		$a_80_2 = {73 65 6e 64 44 69 73 63 6f 72 64 57 65 62 68 6f 6f 6b } //sendDiscordWebhook  3
		$a_80_3 = {5a 65 64 69 6e 20 6c 6f 67 67 65 72 } //Zedin logger  3
		$a_80_4 = {5c 64 69 73 63 6f 72 64 5c 4c 6f 63 61 6c 20 53 74 6f 72 61 67 65 5c 6c 65 76 65 6c 64 62 5c } //\discord\Local Storage\leveldb\  3
		$a_80_5 = {5b 61 2d 7a 41 2d 5a 30 2d 39 5d 7b 32 34 7d 5c 2e 5b 61 2d 7a 41 2d 5a 30 2d 39 5d 7b 36 7d 5c 2e 5b 61 2d 7a 41 2d 5a 30 2d 39 5f 5c 2d 5d 7b 32 37 7d 7c 6d 66 61 5c 2e 5b 61 2d 7a 41 2d 5a 30 2d 39 5f 5c 2d 5d 7b 38 34 7d } //[a-zA-Z0-9]{24}\.[a-zA-Z0-9]{6}\.[a-zA-Z0-9_\-]{27}|mfa\.[a-zA-Z0-9_\-]{84}  3
		$a_80_6 = {47 65 74 57 69 6e 49 6e 66 6f } //GetWinInfo  3
	condition:
		((#a_80_0  & 1)*3+(#a_80_1  & 1)*3+(#a_80_2  & 1)*3+(#a_80_3  & 1)*3+(#a_80_4  & 1)*3+(#a_80_5  & 1)*3+(#a_80_6  & 1)*3) >=21
 
}