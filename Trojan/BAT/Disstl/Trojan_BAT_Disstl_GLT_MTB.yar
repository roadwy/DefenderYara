
rule Trojan_BAT_Disstl_GLT_MTB{
	meta:
		description = "Trojan:BAT/Disstl.GLT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_80_0 = {44 6f 77 6e 6c 6f 61 64 53 74 72 69 6e 67 } //DownloadString  01 00 
		$a_80_1 = {68 74 74 70 73 3a 2f 2f 64 69 73 7b 30 7d 64 2e 63 6f 6d 2f 61 70 69 2f 77 65 62 68 6f 6f 6b 73 2f 38 39 39 32 37 38 32 37 32 31 37 39 38 36 33 36 34 32 2f 43 72 50 72 51 71 62 57 62 34 35 37 30 4c 69 75 5f 76 6a 6d 4d 72 44 36 32 39 49 6d 53 4b 77 70 45 72 6b 39 62 38 38 54 64 6d 65 77 43 64 68 46 38 7a 5f 49 57 48 31 4c 33 41 6d 71 56 35 6d 48 70 50 6b 58 } //https://dis{0}d.com/api/webhooks/899278272179863642/CrPrQqbWb4570Liu_vjmMrD629ImSKwpErk9b88TdmewCdhF8z_IWH1L3AmqV5mHpPkX  01 00 
		$a_80_2 = {68 74 74 70 73 3a 2f 2f 64 69 73 63 6f 72 64 61 70 70 2e 63 6f 6d 2f 61 70 69 2f 76 36 2f 75 73 65 72 73 2f 40 6d 65 } //https://discordapp.com/api/v6/users/@me  01 00 
		$a_80_3 = {68 74 74 70 73 3a 2f 2f 64 69 73 63 6f 72 64 61 70 70 2e 63 6f 6d 2f 61 70 69 2f 76 36 2f 75 73 65 72 73 2f 40 6d 65 2f 62 69 6c 6c 69 6e 67 2f 70 61 79 6d 65 6e 74 73 } //https://discordapp.com/api/v6/users/@me/billing/payments  01 00 
		$a_80_4 = {68 74 74 70 73 3a 2f 2f 64 69 73 63 6f 72 64 61 70 70 2e 63 6f 6d 2f 61 70 69 2f 76 36 2f 75 73 65 72 73 2f 40 6d 65 2f 67 75 69 6c 64 73 } //https://discordapp.com/api/v6/users/@me/guilds  01 00 
		$a_80_5 = {68 74 74 70 73 3a 2f 2f 64 69 73 63 6f 72 64 61 70 70 2e 63 6f 6d 2f 61 70 69 2f 76 36 2f 75 73 65 72 73 2f 40 6d 65 2f 72 65 6c 61 74 69 6f 6e 73 68 69 70 73 } //https://discordapp.com/api/v6/users/@me/relationships  00 00 
	condition:
		any of ($a_*)
 
}