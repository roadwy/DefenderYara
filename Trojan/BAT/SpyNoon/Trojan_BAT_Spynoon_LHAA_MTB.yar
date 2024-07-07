
rule Trojan_BAT_Spynoon_LHAA_MTB{
	meta:
		description = "Trojan:BAT/Spynoon.LHAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {0a 72 72 f8 03 70 72 76 f8 03 70 17 8d 90 01 01 00 00 01 25 16 1f 2d 9d 28 90 01 01 00 00 0a 28 90 01 01 00 00 0a 20 00 01 00 00 14 14 17 8d 90 01 01 00 00 01 25 16 06 72 80 f8 03 70 72 84 f8 03 70 6f 90 01 01 00 00 0a 28 90 01 01 00 00 06 a2 90 00 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}