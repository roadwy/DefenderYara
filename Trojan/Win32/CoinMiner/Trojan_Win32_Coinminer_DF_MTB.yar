
rule Trojan_Win32_CoinMiner_DF_MTB{
	meta:
		description = "Trojan:Win32/CoinMiner.DF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {33 d0 8b 4d f0 c1 e9 05 03 4d d8 33 d1 8b 45 d4 2b c2 89 45 d4 8b 4d e8 2b 4d dc 89 4d e8 e9 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}