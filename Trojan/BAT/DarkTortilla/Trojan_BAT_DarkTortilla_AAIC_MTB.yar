
rule Trojan_BAT_DarkTortilla_AAIC_MTB{
	meta:
		description = "Trojan:BAT/DarkTortilla.AAIC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 05 00 "
		
	strings :
		$a_03_0 = {01 25 16 07 8c 90 01 01 00 00 01 a2 25 17 11 04 1f 12 61 8c 90 01 01 00 00 01 a2 14 28 90 01 01 00 00 0a 1e 13 07 38 90 01 01 fe ff ff 1f 0b 13 07 38 90 01 01 fe ff ff 07 17 d6 0b 1c 13 07 38 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}