
rule Trojan_BAT_RevengeRat_AAF_MTB{
	meta:
		description = "Trojan:BAT/RevengeRat.AAF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {17 59 13 06 2b 20 00 07 06 11 06 6f 0b 00 00 0a 13 07 12 07 28 0c 00 00 0a 28 0d 00 00 0a 0b 00 11 06 17 59 13 06 11 06 16 fe 04 16 fe 01 13 08 11 08 2d d2 } //00 00 
	condition:
		any of ($a_*)
 
}