
rule TrojanDownloader_BAT_RemcosRAT_H_MTB{
	meta:
		description = "TrojanDownloader:BAT/RemcosRAT.H!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 02 00 "
		
	strings :
		$a_03_0 = {0a 0b 06 6f 90 01 01 00 00 0a 17 3e 90 01 01 00 00 00 07 72 90 01 01 00 00 70 6f 90 01 01 00 00 0a 0c 06 6f 90 01 01 00 00 0a 6f 90 01 01 00 00 0a 16 3e 90 01 01 00 00 00 08 72 90 01 01 00 00 70 6f 90 01 01 00 00 0a 0d 06 6f 90 00 } //02 00 
		$a_03_1 = {0a 17 6a 3e 90 01 01 00 00 00 d0 90 01 01 00 00 01 28 90 01 01 00 00 0a 09 28 90 01 01 00 00 0a 74 90 01 01 00 00 01 13 04 06 6f 90 01 01 00 00 0a 26 73 90 01 01 00 00 0a 11 04 28 90 01 01 00 00 0a 6f 90 00 } //01 00 
		$a_01_2 = {47 65 74 52 65 73 70 6f 6e 73 65 } //00 00  GetResponse
	condition:
		any of ($a_*)
 
}