
rule Trojan_BAT_CoinMiner_AYC_MTB{
	meta:
		description = "Trojan:BAT/CoinMiner.AYC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {03 07 11 05 58 17 6f ?? ?? ?? 0a 72 a0 c1 00 70 02 7b 09 00 00 04 28 ?? ?? ?? 0a 73 22 00 00 0a 7a 09 11 06 6e 11 04 17 58 1e 5a 11 05 1b 5a 59 1b 59 1f 3f 5f 62 60 0d 11 05 17 58 13 05 11 05 08 32 9e } //2
		$a_01_1 = {5c 00 45 00 78 00 61 00 6d 00 70 00 6c 00 65 00 2e 00 65 00 78 00 65 00 } //1 \Example.exe
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}