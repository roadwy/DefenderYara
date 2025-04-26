
rule Trojan_BAT_CoinMiner_ABJA_MTB{
	meta:
		description = "Trojan:BAT/CoinMiner.ABJA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_03_0 = {08 03 2d 18 07 06 28 ?? ?? ?? 0a 72 ?? ?? ?? 70 6f ?? ?? ?? 0a 6f ?? ?? ?? 0a 2b 16 07 06 28 ?? ?? ?? 0a 72 ?? ?? ?? 70 6f ?? ?? ?? 0a 6f ?? ?? ?? 0a 17 73 ?? ?? ?? 0a 0d 09 02 16 02 8e 69 6f ?? ?? ?? 0a 09 6f ?? ?? ?? 0a de 0a 09 2c 06 09 6f ?? ?? ?? 0a dc } //2
		$a_01_1 = {63 00 67 00 78 00 6b 00 67 00 6c 00 71 00 61 00 64 00 } //1 cgxkglqad
		$a_01_2 = {73 00 72 00 70 00 72 00 63 00 66 00 61 00 78 00 62 00 76 00 65 00 6f 00 72 00 75 00 67 00 63 00 } //1 srprcfaxbveorugc
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=4
 
}