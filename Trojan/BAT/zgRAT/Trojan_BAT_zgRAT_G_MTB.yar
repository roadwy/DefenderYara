
rule Trojan_BAT_zgRAT_G_MTB{
	meta:
		description = "Trojan:BAT/zgRAT.G!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_03_0 = {06 08 06 91 20 90 01 03 28 28 90 01 01 00 00 06 28 90 01 01 00 00 0a 59 d2 9c 06 17 58 0a 06 08 8e 69 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}