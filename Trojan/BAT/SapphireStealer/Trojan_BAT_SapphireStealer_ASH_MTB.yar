
rule Trojan_BAT_SapphireStealer_ASH_MTB{
	meta:
		description = "Trojan:BAT/SapphireStealer.ASH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {18 5a 1f 16 58 0a 2b 43 06 09 5d 13 05 06 11 07 5d 13 0b 07 11 05 91 13 0c 11 04 11 0b 6f 90 01 03 0a 13 0d 07 06 17 58 09 5d 91 13 0e 11 0c 11 0d 11 0e 28 90 01 03 06 13 0f 07 11 05 11 0f 20 00 01 00 00 5d d2 9c 06 17 59 0a 06 16 fe 04 16 fe 01 13 10 11 10 2d b0 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}