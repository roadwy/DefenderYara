
rule Trojan_BAT_Disstl_AD_MTB{
	meta:
		description = "Trojan:BAT/Disstl.AD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,15 00 15 00 07 00 00 03 00 "
		
	strings :
		$a_80_0 = {4d 42 5f 47 72 61 62 62 65 72 } //MB_Grabber  03 00 
		$a_80_1 = {44 69 73 63 6f 72 64 44 65 76 65 6c 6f 70 6d 65 6e 74 } //DiscordDevelopment  03 00 
		$a_80_2 = {67 65 74 49 6e 66 6f } //getInfo  03 00 
		$a_80_3 = {28 6d 66 61 5c 2e 5b 61 2d 7a 30 2d 39 5f 2d 5d 7b 32 30 2c 7d 29 7c 28 5b 61 2d 7a 30 2d 39 5f 2d 5d 7b 32 33 2c 32 38 7d 5c 2e 5b 61 2d 7a 30 2d 39 5f 2d 5d 7b 36 2c 37 7d 5c 2e 5b 61 2d 7a 30 2d 39 5f 2d 5d 7b 32 37 7d 29 } //(mfa\.[a-z0-9_-]{20,})|([a-z0-9_-]{23,28}\.[a-z0-9_-]{6,7}\.[a-z0-9_-]{27})  03 00 
		$a_80_4 = {57 65 62 68 6f 6f 6b 4d 65 73 73 61 67 65 } //WebhookMessage  03 00 
		$a_80_5 = {67 65 74 5f 61 76 61 74 61 72 5f 75 72 6c } //get_avatar_url  03 00 
		$a_80_6 = {64 6f 54 68 65 45 6d 65 72 67 65 6e 63 79 54 68 69 6e 67 } //doTheEmergencyThing  00 00 
	condition:
		any of ($a_*)
 
}