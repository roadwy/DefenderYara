
rule Trojan_BAT_Spynoon_AAEG_MTB{
	meta:
		description = "Trojan:BAT/Spynoon.AAEG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {13 0c 11 0c 18 6f 90 01 01 00 00 0a 00 11 0c 18 6f 90 01 01 00 00 0a 00 11 0c 72 0d c2 12 70 28 90 01 01 00 00 0a 6f 90 01 01 00 00 0a 00 11 0c 6f 90 01 01 00 00 0a 13 0d 11 0d 06 16 06 8e 69 6f 90 01 01 00 00 0a 13 0e 90 00 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}