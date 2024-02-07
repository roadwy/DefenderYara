
rule Trojan_BAT_DiscordStealer_XO_MTB{
	meta:
		description = "Trojan:BAT/DiscordStealer.XO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 01 00 "
		
	strings :
		$a_01_0 = {4c 69 6d 65 72 42 6f 79 2f 53 74 6f 72 6d 4b 69 74 74 79 } //01 00  LimerBoy/StormKitty
		$a_80_1 = {52 6f 62 6c 6f 78 53 74 75 64 69 6f 42 72 6f 77 73 65 72 5c 72 6f 62 6c 6f 78 2e 63 6f 6d } //RobloxStudioBrowser\roblox.com  01 00 
		$a_01_2 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //01 00  FromBase64String
		$a_01_3 = {46 75 63 6b 2e 54 68 61 74 2e 42 69 74 63 68 2e 4b 61 72 65 6e 2e 49 2e 54 61 6b 65 2e 48 65 72 2e 54 6f 2e 43 6f 75 72 74 } //01 00  Fuck.That.Bitch.Karen.I.Take.Her.To.Court
		$a_01_4 = {49 6e 76 6f 6b 65 } //01 00  Invoke
		$a_01_5 = {44 65 63 72 79 70 74 44 69 73 63 6f 72 64 54 6f 6b 65 6e } //01 00  DecryptDiscordToken
		$a_80_6 = {65 6e 63 72 79 70 74 65 64 5f 6b 65 79 } //encrypted_key  01 00 
		$a_80_7 = {5c 70 61 73 73 77 6f 72 64 73 2e 74 78 74 } //\passwords.txt  00 00 
	condition:
		any of ($a_*)
 
}