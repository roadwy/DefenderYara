
rule Trojan_BAT_Spynoon_ASBI_MTB{
	meta:
		description = "Trojan:BAT/Spynoon.ASBI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {0d 16 13 06 2b 23 00 08 11 06 18 6f 90 01 01 00 00 0a 13 07 09 11 06 18 5b 11 07 1f 10 28 90 01 01 00 00 0a d2 9c 00 11 06 18 58 13 06 11 06 08 6f 90 01 01 00 00 0a fe 04 13 08 11 08 2d cd 90 00 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}