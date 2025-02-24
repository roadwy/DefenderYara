
rule Trojan_Win32_CoinMiner_GNT_MTB{
	meta:
		description = "Trojan:Win32/CoinMiner.GNT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_03_0 = {4a 1c 6f a3 ?? ?? ?? ?? 6b 37 70 11 56 ?? ec 93 } //5
		$a_01_1 = {30 53 1d 2c 7c b3 e7 4a } //5
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*5) >=10
 
}