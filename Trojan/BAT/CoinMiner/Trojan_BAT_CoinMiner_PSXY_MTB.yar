
rule Trojan_BAT_CoinMiner_PSXY_MTB{
	meta:
		description = "Trojan:BAT/CoinMiner.PSXY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_01_0 = {0a 72 01 00 00 70 73 05 00 00 0a 0b 72 39 00 00 70 73 05 00 00 0a 0c 06 07 72 77 00 00 70 6f 06 00 00 0a 06 08 } //00 00 
	condition:
		any of ($a_*)
 
}