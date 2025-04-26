
rule Trojan_BAT_CoinMiner_KAA_MTB{
	meta:
		description = "Trojan:BAT/CoinMiner.KAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {11 04 11 05 02 11 05 91 06 61 08 09 91 61 b4 9c 09 03 6f ?? 00 00 0a 17 da 33 04 16 0d 2b 04 09 17 d6 0d 11 05 17 d6 13 05 11 05 11 06 31 d1 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}