
rule Trojan_Win64_CoinMiner_PPCD_MTB{
	meta:
		description = "Trojan:Win64/CoinMiner.PPCD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_01_0 = {48 89 44 24 60 48 8b 44 24 60 8b 40 10 48 8b 4c 24 60 8b 49 14 48 8b 94 24 30 01 00 00 48 03 d1 48 8b ca 48 8b 54 24 60 8b 52 0c 4c 8b 44 24 68 4c 03 c2 49 8b d0 48 c7 44 24 20 00 00 00 00 44 8b c8 4c 8b c1 48 8b 4c 24 78 ff 15 } //4
		$a_01_1 = {41 b9 20 00 00 00 44 8b c0 48 8b d1 48 8b 4c 24 78 ff 15 } //2
	condition:
		((#a_01_0  & 1)*4+(#a_01_1  & 1)*2) >=6
 
}