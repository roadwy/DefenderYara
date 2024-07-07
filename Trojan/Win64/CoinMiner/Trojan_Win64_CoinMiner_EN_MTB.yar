
rule Trojan_Win64_CoinMiner_EN_MTB{
	meta:
		description = "Trojan:Win64/CoinMiner.EN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {33 d2 49 63 ca 49 3b c9 48 0f 45 d6 42 8a 04 02 48 8d 72 01 30 03 33 c0 49 3b c9 41 0f 45 c2 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}