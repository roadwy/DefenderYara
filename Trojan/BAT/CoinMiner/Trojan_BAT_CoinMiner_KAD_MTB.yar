
rule Trojan_BAT_CoinMiner_KAD_MTB{
	meta:
		description = "Trojan:BAT/CoinMiner.KAD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {09 11 04 9a 6f ?? 00 00 0a 06 6f ?? 00 00 0a 2c 09 07 17 58 0b 07 17 31 01 2a 11 04 17 58 13 04 11 04 09 8e 69 32 d9 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}