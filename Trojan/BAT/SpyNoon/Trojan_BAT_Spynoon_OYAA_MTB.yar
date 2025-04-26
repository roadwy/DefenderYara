
rule Trojan_BAT_Spynoon_OYAA_MTB{
	meta:
		description = "Trojan:BAT/Spynoon.OYAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {11 05 11 11 91 11 12 61 13 13 11 11 17 58 11 05 8e 69 5d 13 14 11 05 11 14 91 13 15 11 13 11 15 59 20 00 01 00 00 58 20 ff 00 00 00 5f 13 16 11 05 11 11 11 16 d2 9c 00 11 11 17 58 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}