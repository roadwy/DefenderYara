
rule Trojan_BAT_CoinMiner_GPD_MTB{
	meta:
		description = "Trojan:BAT/CoinMiner.GPD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_01_0 = {70 00 6f 00 6f 00 6c 00 2e 00 6d 00 69 00 6e 00 65 00 78 00 6d 00 72 00 2e 00 63 00 6f 00 6d 00 3a 00 34 00 34 00 34 00 34 00 } //5 pool.minexmr.com:4444
		$a_01_1 = {6d 00 6f 00 6e 00 65 00 72 00 6f 00 73 00 70 00 65 00 6c 00 75 00 6e 00 6b 00 65 00 72 00 2e 00 63 00 6f 00 6e 00 66 00 } //5 monerospelunker.conf
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*5) >=10
 
}