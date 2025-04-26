
rule Trojan_Win32_CoinMiner_MC_MTB{
	meta:
		description = "Trojan:Win32/CoinMiner.MC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b d3 c1 ea 08 8b 88 cc 00 00 00 a1 98 a2 08 10 88 14 08 ff 05 98 a2 08 10 8b 15 d4 99 05 10 8b 86 90 00 00 00 8b 8a b0 00 00 00 81 c1 3b 30 f8 ff 03 c1 09 82 c0 00 00 00 8b 46 78 8b 8e cc 00 00 00 88 1c 01 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}