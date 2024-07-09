
rule TrojanDownloader_BAT_Small_ASM_MTB{
	meta:
		description = "TrojanDownloader:BAT/Small.ASM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {13 08 16 13 09 2b 43 11 08 11 09 9a 0d 00 09 6f ?? ?? ?? 0a 72 a5 00 00 70 6f ?? ?? ?? 0a 16 fe 01 13 0a 11 0a 2d 1c 00 12 02 08 8e 69 17 58 28 ?? ?? ?? 2b 00 08 08 8e 69 17 59 09 6f ?? ?? ?? 0a a2 00 00 11 09 17 58 13 09 11 09 11 08 8e 69 fe 04 13 0a 11 0a 2d af } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule TrojanDownloader_BAT_Small_ASM_MTB_2{
	meta:
		description = "TrojanDownloader:BAT/Small.ASM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0a 06 25 28 ?? 00 00 0a 17 8d ?? 00 00 01 25 16 72 ?? 00 00 70 a2 28 ?? 00 00 0a 02 7b ?? 00 00 0a 28 ?? 00 00 0a 7d ?? 00 00 0a 18 8d ?? 00 00 01 25 16 72 ?? 00 00 70 a2 25 17 16 8c ?? 00 00 01 a2 16 16 02 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}