
rule TrojanDownloader_BAT_SnakeKeylogger_H_MTB{
	meta:
		description = "TrojanDownloader:BAT/SnakeKeylogger.H!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {02 16 02 8e 69 ?? 3a ?? 00 00 00 26 26 26 38 ?? 00 00 00 28 ?? 00 00 0a 38 00 00 00 00 2a } //1
		$a_03_1 = {00 00 0a 0b 20 00 ?? 00 00 8d ?? 00 00 01 0c 16 0d 07 08 16 08 8e 69 6f ?? 00 00 0a 0d 12 ?? 08 09 28 ?? 00 00 06 09 16 fe ?? 13 ?? 11 ?? 3a ?? ?? ff ff 11 05 6f } //1
		$a_03_2 = {00 00 0a 74 0a 00 00 01 ?? 3a ?? 00 00 00 26 06 38 ?? 00 00 00 0a 38 ?? ff ff ff 2a } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}