
rule Trojan_BAT_Spynoon_AASA_MTB{
	meta:
		description = "Trojan:BAT/Spynoon.AASA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {11 11 07 8e 69 5d 13 12 11 11 08 6f ?? 00 00 0a 5d 13 13 07 11 12 91 13 14 08 11 13 6f ?? 00 00 0a 13 15 02 07 11 11 28 ?? 00 00 06 13 16 02 11 14 11 15 11 16 28 ?? 00 00 06 13 17 07 11 12 02 11 17 28 ?? 00 00 06 9c 00 11 11 17 59 13 11 11 11 16 fe 04 16 fe 01 13 18 11 18 2d a2 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}