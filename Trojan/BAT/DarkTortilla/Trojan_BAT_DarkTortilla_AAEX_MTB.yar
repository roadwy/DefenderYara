
rule Trojan_BAT_DarkTortilla_AAEX_MTB{
	meta:
		description = "Trojan:BAT/DarkTortilla.AAEX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 05 00 "
		
	strings :
		$a_03_0 = {01 25 16 07 8c 90 01 01 00 00 01 a2 14 28 90 01 01 00 00 0a 28 90 01 01 00 00 0a 13 04 1f 0b 13 07 38 90 01 01 ff ff ff 02 18 8d 90 01 01 00 00 01 25 16 07 8c 90 01 01 00 00 01 a2 25 17 11 04 1f 48 61 8c 90 01 01 00 00 01 a2 14 28 90 01 01 00 00 0a 1a 13 07 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}