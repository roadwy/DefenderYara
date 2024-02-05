
rule Trojan_BAT_StormKitty_NEAC_MTB{
	meta:
		description = "Trojan:BAT/StormKitty.NEAC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 02 00 00 0a 00 "
		
	strings :
		$a_01_0 = {58 9e 09 11 04 11 09 d2 9c 09 11 04 17 58 11 09 1e 64 d2 9c 09 11 04 18 58 11 09 1f 10 64 d2 9c 09 11 04 19 58 11 09 1f 18 64 d2 9c 11 04 1a 58 13 04 11 08 17 58 13 08 11 08 02 8e 69 32 9e } //05 00 
		$a_01_1 = {64 66 67 72 75 73 65 64 6a 6b 79 2e 65 78 65 } //00 00 
	condition:
		any of ($a_*)
 
}