
rule Trojan_BAT_DiscordStealer_SZ_MTB{
	meta:
		description = "Trojan:BAT/DiscordStealer.SZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 02 00 "
		
	strings :
		$a_01_0 = {00 09 28 04 00 00 06 17 8d 24 00 00 01 25 16 1f 22 9d 6f 24 00 00 0a 13 06 11 06 16 9a 0c 72 5d 02 00 70 11 06 28 25 00 00 0a 0d 03 2c 0c 08 6f 26 00 00 0a 1f 3b fe 01 2b 01 16 13 07 11 07 2c 03 00 2b 16 00 09 11 04 11 05 28 13 00 00 0a 6f 20 00 00 0a 13 08 11 08 2d a6 } //02 00 
		$a_01_1 = {7a 69 67 67 79 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 } //00 00  ziggy.Properties.Resources
	condition:
		any of ($a_*)
 
}