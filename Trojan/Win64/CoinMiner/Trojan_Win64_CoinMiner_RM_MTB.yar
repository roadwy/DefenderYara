
rule Trojan_Win64_CoinMiner_RM_MTB{
	meta:
		description = "Trojan:Win64/CoinMiner.RM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8a 02 34 3c 88 02 48 ff c2 8a 02 34 e8 88 02 48 ff c2 48 ff ce 75 e9 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}