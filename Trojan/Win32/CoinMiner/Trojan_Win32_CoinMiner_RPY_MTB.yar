
rule Trojan_Win32_CoinMiner_RPY_MTB{
	meta:
		description = "Trojan:Win32/CoinMiner.RPY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {55 8b ec 51 53 57 e8 95 b1 04 00 68 2a 03 00 00 e8 8b c2 20 00 8b 0d d0 26 66 00 83 c4 04 03 c8 89 0d d0 26 66 00 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}