
rule Trojan_Win64_CoinMiner_XZ_MTB{
	meta:
		description = "Trojan:Win64/CoinMiner.XZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {02 c2 40 02 c5 40 02 c7 45 3b c4 0f b6 e8 44 0f 4d c3 49 ff c1 41 8b 44 ab 08 43 89 44 8b 04 41 89 7c ab 08 } //00 00 
	condition:
		any of ($a_*)
 
}