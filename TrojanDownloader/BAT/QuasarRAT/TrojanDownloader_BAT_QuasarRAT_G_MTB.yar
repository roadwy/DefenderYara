
rule TrojanDownloader_BAT_QuasarRAT_G_MTB{
	meta:
		description = "TrojanDownloader:BAT/QuasarRAT.G!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_03_0 = {06 07 02 07 18 5a 18 6f ?? 00 00 0a 1f 10 28 ?? 00 00 0a 9c 07 17 58 0b 07 06 8e 69 32 e2 06 2a } //2
		$a_03_1 = {13 06 19 8d ?? 00 00 01 13 ?? 11 ?? 16 28 ?? 00 00 0a 6f ?? 00 00 0a a2 11 ?? 17 7e ?? 00 00 0a a2 11 ?? 18 06 11 06 6f ?? 00 00 0a a2 11 ?? 13 ?? 06 11 04 6f } //2
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*2) >=4
 
}