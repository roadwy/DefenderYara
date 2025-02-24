
rule Trojan_Win64_CoinMiner_ASJ_MTB{
	meta:
		description = "Trojan:Win64/CoinMiner.ASJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {48 01 d0 0f b6 00 89 c1 8b 85 ?? ?? 00 00 48 8b 95 ?? ?? 00 00 48 01 c2 89 c8 32 85 ?? ?? 00 00 88 02 83 85 ?? ?? 00 00 01 8b 85 ?? ?? 00 00 39 85 ?? ?? 00 00 72 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}