
rule Trojan_BAT_Spynoon_AAUY_MTB{
	meta:
		description = "Trojan:BAT/Spynoon.AAUY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {07 11 10 07 8e 69 6a 5d d4 91 08 11 10 08 8e 69 6a 5d d4 91 61 07 11 10 17 6a 58 07 8e 69 6a 5d d4 91 59 20 00 01 00 00 58 13 11 07 11 10 07 8e 69 6a 5d d4 11 11 20 00 01 00 00 5d d2 9c 00 11 10 17 6a 58 13 10 11 10 07 8e 69 17 59 09 17 58 5a 6a fe 02 16 fe 01 13 12 11 12 2d a2 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}