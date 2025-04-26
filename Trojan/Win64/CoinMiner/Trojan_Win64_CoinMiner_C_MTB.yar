
rule Trojan_Win64_CoinMiner_C_MTB{
	meta:
		description = "Trojan:Win64/CoinMiner.C!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {85 c1 5f a9 ?? ?? ?? ?? 30 8c 83 ?? ?? ?? ?? 21 ed d6 c0 d3 ?? ed d5 79 52 6d 8b 30 80 e2 ?? 9c e9 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}