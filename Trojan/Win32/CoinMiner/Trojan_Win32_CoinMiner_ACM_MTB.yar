
rule Trojan_Win32_CoinMiner_ACM_MTB{
	meta:
		description = "Trojan:Win32/CoinMiner.ACM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {83 c1 10 6a 08 83 d0 00 50 51 8b 4c 24 20 e8 ?? ?? ?? ?? 8b 7c 24 1c 8d 94 24 f0 00 00 00 8b 44 24 18 83 c4 10 8b cf 81 c1 e0 73 08 00 89 8c 24 60 01 00 00 8b 4c 24 14 83 d0 00 89 84 24 64 01 00 00 } //3
		$a_01_1 = {8b d9 8b f2 8b d3 57 8d 7a 02 8d 64 24 00 66 8b 02 83 c2 02 66 85 c0 75 f5 8b ce 2b d7 d1 fa 8d 79 02 66 8b 01 83 c1 02 66 85 c0 75 f5 2b cf 8d 42 01 d1 f9 ba 02 00 00 00 03 c1 33 c9 f7 e2 0f 90 c1 f7 d9 0b c8 51 } //2
	condition:
		((#a_03_0  & 1)*3+(#a_01_1  & 1)*2) >=5
 
}