
rule Trojan_BAT_CoinMiner_NBL_MTB{
	meta:
		description = "Trojan:BAT/CoinMiner.NBL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {20 a5 dd fe 71 11 0e 20 00 00 00 04 5c 61 16 2e 03 2b 0e 00 20 b6 ?? ?? ?? 20 6f 37 cf df 61 2b 09 7e 4e ?? ?? ?? 8e 1f 17 58 } //1
		$a_01_1 = {06 5f 61 16 33 15 00 06 20 00 20 00 00 5a 20 79 02 00 00 33 06 38 da 00 00 00 00 06 20 70 92 00 00 5a 20 84 15 00 00 61 16 2e 02 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}