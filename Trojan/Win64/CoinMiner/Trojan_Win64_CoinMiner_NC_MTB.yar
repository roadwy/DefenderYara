
rule Trojan_Win64_CoinMiner_NC_MTB{
	meta:
		description = "Trojan:Win64/CoinMiner.NC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {74 0c 83 fa ?? 75 2a e8 2a 08 00 00 eb 23 48 8d 1d ?? ?? ?? ?? 48 8d 35 45 92 53 00 48 39 f3 } //5
		$a_01_1 = {6f 70 65 6f 68 63 7a } //1 opeohcz
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1) >=6
 
}