
rule Trojan_Win64_CoinMiner_AB_MTB{
	meta:
		description = "Trojan:Win64/CoinMiner.AB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 05 00 "
		
	strings :
		$a_01_0 = {31 c0 48 89 c1 48 89 d7 83 e1 07 48 c1 e1 03 48 d3 ef 66 41 31 3c 44 48 83 c0 01 48 83 f8 1b 75 e1 } //00 00 
	condition:
		any of ($a_*)
 
}