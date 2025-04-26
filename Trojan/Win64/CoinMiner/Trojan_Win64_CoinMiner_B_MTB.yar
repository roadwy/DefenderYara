
rule Trojan_Win64_CoinMiner_B_MTB{
	meta:
		description = "Trojan:Win64/CoinMiner.B!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_03_0 = {68 1e 61 9a a1 9c 48 8b 7c 24 08 40 c0 e7 94 48 f7 df 48 8b bc 3c 10 61 9a a1 48 c7 44 24 10 4b 71 f5 0b ff 74 24 00 9d 48 8d ?? ?? ?? e8 ?? ?? ?? ?? 48 c7 44 24 00 2f 7a ce 79 e8 ?? ?? ?? ?? aa bb d0 00 4a ea f8 c8 32 03 78 } //2
		$a_01_1 = {c1 e8 0b 80 fb 9f f9 0f af c1 f9 45 84 f0 3b f8 0f 83 2b 00 00 00 44 8b c0 66 35 1d a0 66 40 0f b6 c4 b8 00 08 00 00 2b c1 f9 c1 f8 05 66 03 c1 03 d2 66 42 89 04 5e e9 00 00 00 00 } //2
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*2) >=4
 
}