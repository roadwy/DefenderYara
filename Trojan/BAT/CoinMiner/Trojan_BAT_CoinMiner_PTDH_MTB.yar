
rule Trojan_BAT_CoinMiner_PTDH_MTB{
	meta:
		description = "Trojan:BAT/CoinMiner.PTDH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {7e c0 5d 00 04 28 ?? 01 00 06 28 ?? 00 00 06 28 ?? 01 00 06 28 ?? 00 00 0a 28 ?? 00 00 0a 28 ?? 00 00 0a 13 09 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}