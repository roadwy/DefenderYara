
rule Trojan_BAT_Spynoon_NMAA_MTB{
	meta:
		description = "Trojan:BAT/Spynoon.NMAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {06 17 58 09 5d 13 07 07 11 07 91 13 08 02 07 06 91 11 06 61 11 08 28 90 01 01 00 00 06 13 09 07 06 11 09 28 90 01 01 00 00 0a 9c 06 17 58 0a 90 00 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}