
rule Trojan_BAT_CoinMiner_PSCF_MTB{
	meta:
		description = "Trojan:BAT/CoinMiner.PSCF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {08 03 2d 18 07 06 28 1e 00 00 0a 72 19 07 00 70 6f 1f 00 00 0a 6f 24 00 00 0a 2b 16 07 06 28 1e 00 00 0a 72 19 07 00 70 6f 1f 00 00 0a 6f 25 00 00 0a 17 73 26 00 00 0a 0d } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}