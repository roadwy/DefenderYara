
rule Trojan_BAT_Donut_KA_MTB{
	meta:
		description = "Trojan:BAT/Donut.KA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_03_0 = {00 06 08 18 73 90 01 01 00 00 0a 0d 07 09 90 01 05 28 0a 00 00 0a 6f 90 01 01 00 00 0a 00 00 08 18 58 0c 08 06 8e 69 fe 04 13 05 11 05 2d d3 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}