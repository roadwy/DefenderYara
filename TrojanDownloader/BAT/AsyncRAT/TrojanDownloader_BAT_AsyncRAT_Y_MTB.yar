
rule TrojanDownloader_BAT_AsyncRAT_Y_MTB{
	meta:
		description = "TrojanDownloader:BAT/AsyncRAT.Y!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_03_0 = {0a 11 0c 6f ?? 00 00 0a 13 0d ?? [0-01] 72 01 00 00 70 17 8d ?? 00 00 01 13 0e 11 0e 16 11 09 a4 ?? 00 00 01 11 0e 28 ?? 00 00 0a 6f ?? 00 00 0a 72 01 00 00 70 17 8d ?? 00 00 01 13 0f 11 0f 16 11 0d a4 ?? 00 00 01 11 0f 28 ?? 00 00 0a 20 00 01 00 00 14 14 11 0b 74 ?? 00 00 1b 6f ?? 00 00 0a 26 dd } //2
		$a_03_1 = {0a 13 06 28 ?? 00 00 0a 11 06 6f ?? 00 00 0a 13 07 1f 38 8d } //2
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*2) >=4
 
}