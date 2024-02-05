
rule Trojan_BAT_DarkTortilla_AALP_MTB{
	meta:
		description = "Trojan:BAT/DarkTortilla.AALP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 05 00 "
		
	strings :
		$a_03_0 = {0a 13 07 07 75 90 01 01 00 00 1b 11 07 28 90 01 01 00 00 0a 03 28 90 01 01 00 00 06 b4 6f 90 01 01 00 00 0a 1a 13 0c 38 90 01 01 ff ff ff 08 17 d6 0c 1c 13 0c 38 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}