
rule Trojan_BAT_Spynoon_AAWG_MTB{
	meta:
		description = "Trojan:BAT/Spynoon.AAWG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {11 08 11 04 5d 13 09 11 08 1f 16 5d 13 0a 11 08 17 58 11 04 5d 13 0b 07 11 09 91 13 0c 20 00 01 00 00 13 0d 11 0c 08 11 0a 91 61 07 11 0b 91 59 11 0d 58 11 0d 5d 13 0e 07 11 09 11 0e d2 9c 00 11 08 17 58 13 08 11 08 11 04 09 17 58 5a fe 04 13 0f 11 0f 2d a9 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}