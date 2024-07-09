
rule Trojan_BAT_Spynoon_AAQA_MTB{
	meta:
		description = "Trojan:BAT/Spynoon.AAQA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {16 13 07 2b 28 08 09 7e ?? 00 00 04 09 91 11 04 11 07 1a 5b 95 11 07 1a 5d 1e 5a 1f 1f 5f 64 d2 61 d2 9c 11 07 17 58 13 07 09 17 58 0d 11 07 1f 10 2f 0c 09 7e ?? 00 00 04 8e 69 fe 04 2b 01 16 13 08 11 08 2d bf } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}