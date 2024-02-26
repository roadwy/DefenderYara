
rule Trojan_BAT_DiscordStealer_GP_MTB{
	meta:
		description = "Trojan:BAT/DiscordStealer.GP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 04 00 "
		
	strings :
		$a_01_0 = {64 00 69 00 73 00 63 00 00 0b 6f 00 72 00 64 00 2e 00 63 00 00 11 6f 00 6d 00 2f 00 61 00 70 00 69 00 2f 00 77 00 00 0b 65 00 62 00 68 00 6f 00 6f 00 00 1f 6b 00 73 00 2f 00 38 00 31 00 30 00 39 00 39 00 34 00 33 00 35 00 34 00 36 00 33 00 33 00 00 31 35 00 37 00 32 00 34 00 33 00 32 } //00 00 
	condition:
		any of ($a_*)
 
}