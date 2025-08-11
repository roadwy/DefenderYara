
rule Trojan_Win32_CoinMiner_ETL_MTB{
	meta:
		description = "Trojan:Win32/CoinMiner.ETL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {89 c1 89 c8 d1 e8 ba 43 08 21 84 f7 e2 89 d0 c1 e8 04 6b c0 3e 29 c1 89 c8 0f b6 80 c0 92 94 62 88 03 83 45 f4 01 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}