
rule Trojan_BAT_AsyncRAT_PLLCH_MTB{
	meta:
		description = "Trojan:BAT/AsyncRAT.PLLCH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {0b 07 8e 69 8d ?? 00 00 01 0c 7e ?? 00 00 04 13 04 2b 18 08 11 04 07 11 04 91 03 11 04 03 8e 69 5d 91 61 d2 9c 11 04 17 58 13 04 11 04 07 8e 69 32 e1 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}