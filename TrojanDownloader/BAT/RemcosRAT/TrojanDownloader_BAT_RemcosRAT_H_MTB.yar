
rule TrojanDownloader_BAT_RemcosRAT_H_MTB{
	meta:
		description = "TrojanDownloader:BAT/RemcosRAT.H!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 "
		
	strings :
		$a_03_0 = {0a 0b 06 6f ?? 00 00 0a 17 3e ?? 00 00 00 07 72 ?? 00 00 70 6f ?? 00 00 0a 0c 06 6f ?? 00 00 0a 6f ?? 00 00 0a 16 3e ?? 00 00 00 08 72 ?? 00 00 70 6f ?? 00 00 0a 0d 06 6f } //2
		$a_03_1 = {0a 17 6a 3e ?? 00 00 00 d0 ?? 00 00 01 28 ?? 00 00 0a 09 28 ?? 00 00 0a 74 ?? 00 00 01 13 04 06 6f ?? 00 00 0a 26 73 ?? 00 00 0a 11 04 28 ?? 00 00 0a 6f } //2
		$a_01_2 = {47 65 74 52 65 73 70 6f 6e 73 65 } //1 GetResponse
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*2+(#a_01_2  & 1)*1) >=5
 
}