
rule TrojanDownloader_BAT_AveMariaRAT_E_MTB{
	meta:
		description = "TrojanDownloader:BAT/AveMariaRAT.E!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {02 16 02 8e 69 ?? 2d ?? 26 26 26 2b ?? 28 ?? 00 00 0a 2b 00 2a } //1
		$a_03_1 = {08 8e 69 6f ?? 00 00 0a 0d 12 ?? 08 09 28 ?? 00 00 06 09 16 fe ?? 13 ?? 11 ?? 2d ?? 11 ?? 6f ?? 00 00 0a 90 0a 3a 00 06 6f ?? 00 00 0a 0b 20 ?? ?? ?? 00 8d ?? 00 00 01 0c 16 0d 07 08 16 } //1
		$a_03_2 = {00 00 0a 74 1b 00 00 01 ?? ?? 04 26 06 2b ?? 0a 2b fa 2a } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}