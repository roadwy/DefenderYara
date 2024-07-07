
rule TrojanDownloader_BAT_SnakeKeylogger_H_MTB{
	meta:
		description = "TrojanDownloader:BAT/SnakeKeylogger.H!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {02 16 02 8e 69 90 01 01 3a 90 01 01 00 00 00 26 26 26 38 90 01 01 00 00 00 28 90 01 01 00 00 0a 38 00 00 00 00 2a 90 00 } //1
		$a_03_1 = {00 00 0a 0b 20 00 90 01 01 00 00 8d 90 01 01 00 00 01 0c 16 0d 07 08 16 08 8e 69 6f 90 01 01 00 00 0a 0d 12 90 01 01 08 09 28 90 01 01 00 00 06 09 16 fe 90 01 01 13 90 01 01 11 90 01 01 3a 90 01 02 ff ff 11 05 6f 90 00 } //1
		$a_03_2 = {00 00 0a 74 0a 00 00 01 90 01 01 3a 90 01 01 00 00 00 26 06 38 90 01 01 00 00 00 0a 38 90 01 01 ff ff ff 2a 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}