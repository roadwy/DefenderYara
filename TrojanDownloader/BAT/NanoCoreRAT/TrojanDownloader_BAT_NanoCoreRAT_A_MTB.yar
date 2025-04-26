
rule TrojanDownloader_BAT_NanoCoreRAT_A_MTB{
	meta:
		description = "TrojanDownloader:BAT/NanoCoreRAT.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_03_0 = {00 00 0a 20 00 01 00 00 14 14 14 6f ?? 00 00 0a 26 2a 90 09 19 00 02 28 ?? 00 00 0a 02 28 ?? 00 00 06 73 ?? 00 00 06 7b ?? 00 00 04 02 6f } //2
		$a_03_1 = {02 2b ce 73 ?? 00 00 0a 2b c9 02 2b d0 28 ?? 00 00 0a 2b cc 02 2b cb 73 ?? 00 00 0a 2b d0 28 ?? 00 00 0a 2b cb 02 2b ca 6f ?? 00 00 0a 2b ca } //2
		$a_03_2 = {06 8e 69 28 ?? 00 00 0a 02 06 28 ?? 00 00 0a 7d ?? 00 00 04 2a 90 09 1a 00 02 28 ?? 00 00 0a 02 28 ?? 00 00 06 02 72 ?? 00 00 70 28 ?? 00 00 06 0a 06 16 } //2
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*2+(#a_03_2  & 1)*2) >=6
 
}