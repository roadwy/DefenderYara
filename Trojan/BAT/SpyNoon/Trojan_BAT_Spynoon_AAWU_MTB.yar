
rule Trojan_BAT_Spynoon_AAWU_MTB{
	meta:
		description = "Trojan:BAT/Spynoon.AAWU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {16 0a 2b 1d 11 04 06 08 06 91 11 05 06 11 05 6f 90 01 01 00 00 0a 5d 6f 90 01 01 00 00 0a 61 d2 9c 06 17 58 0a 06 08 8e 69 32 dd 90 00 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}