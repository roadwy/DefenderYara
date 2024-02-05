
rule Trojan_BAT_SpyStealer_FZA_MTB{
	meta:
		description = "Trojan:BAT/SpyStealer.FZA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {7e 1a 00 00 04 07 7e 1a 00 00 04 07 91 20 90 01 03 00 59 d2 9c 00 07 17 58 0b 07 7e 1a 00 00 04 8e 69 fe 04 0c 08 2d d7 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}