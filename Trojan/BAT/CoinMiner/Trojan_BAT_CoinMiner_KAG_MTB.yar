
rule Trojan_BAT_CoinMiner_KAG_MTB{
	meta:
		description = "Trojan:BAT/CoinMiner.KAG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {07 16 9a 28 ?? 00 00 0a 28 ?? 00 00 06 2c 17 28 ?? 00 00 0a 07 17 9a 28 ?? 00 00 0a 6f ?? 00 00 0a 28 ?? 00 00 0a 11 0c 17 58 13 0c 11 0c 11 0b 8e 69 32 c1 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}