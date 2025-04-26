
rule Trojan_BAT_CoinMiner_ABFJ_MTB{
	meta:
		description = "Trojan:BAT/CoinMiner.ABFJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_03_0 = {08 03 2d 18 07 06 28 ?? ?? ?? 0a 72 ?? ?? ?? 70 6f ?? ?? ?? 0a 6f ?? ?? ?? 0a 2b 16 07 06 28 ?? ?? ?? 0a 72 ?? ?? ?? 70 6f ?? ?? ?? 0a 6f ?? ?? ?? 0a 17 73 ?? ?? ?? 0a 0d 09 02 16 02 8e 69 6f ?? ?? ?? 0a 09 6f ?? ?? ?? 0a de 0a 09 2c 06 09 6f ?? ?? ?? 0a dc 08 6f ?? ?? ?? 0a 13 04 de 14 } //2
		$a_01_1 = {66 00 6f 00 72 00 67 00 72 00 65 00 76 00 68 00 74 00 64 00 6d 00 76 00 6a 00 68 00 78 00 75 00 } //1 forgrevhtdmvjhxu
		$a_01_2 = {73 00 63 00 78 00 79 00 72 00 66 00 64 00 61 00 69 00 72 00 77 00 70 00 6b 00 6b 00 74 00 64 00 7a 00 64 00 67 00 6f 00 61 00 6f 00 61 00 71 00 62 00 71 00 65 00 62 00 75 00 71 00 73 00 72 00 } //1 scxyrfdairwpkktdzdgoaoaqbqebuqsr
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=4
 
}