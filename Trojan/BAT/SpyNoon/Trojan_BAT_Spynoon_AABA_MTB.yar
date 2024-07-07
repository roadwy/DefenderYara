
rule Trojan_BAT_Spynoon_AABA_MTB{
	meta:
		description = "Trojan:BAT/Spynoon.AABA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {16 0a 2b 28 06 09 5d 13 07 06 09 5b 13 08 08 11 07 11 08 6f 90 01 01 00 00 0a 13 0a 11 04 12 0a 28 90 01 01 00 00 0a 6f 90 01 01 00 00 0a 06 17 58 0a 06 09 11 05 5a 32 d1 90 00 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}