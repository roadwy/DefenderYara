
rule TrojanDownloader_BAT_Tnega_ESS_MTB{
	meta:
		description = "TrojanDownloader:BAT/Tnega.ESS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 05 00 00 0a 00 "
		
	strings :
		$a_01_0 = {16 2d cb 16 fe 02 0c 08 2d d9 2b 03 0b 2b f1 06 6f 13 00 00 0a 28 01 00 00 2b 0d 09 2a 73 15 00 00 0a 38 9d ff ff ff 03 38 a0 ff ff ff 0a 38 aa ff ff ff 0b 2b ab 06 2b ac 07 2b ab 03 2b aa 07 2b a9 } //0a 00 
		$a_01_1 = {16 fe 02 0c 2b 07 6f 10 00 00 0a 2b eb 08 2d e1 2b 03 0b 2b eb 06 6f 11 00 00 0a 28 01 00 00 2b 0d 2b 03 26 2b bc 09 2a } //0a 00 
		$a_01_2 = {07 25 17 59 0b 16 fe 02 0c 2b 03 00 2b f2 08 2d 02 2b 09 2b e0 6f 0c 00 00 0a 2b e1 06 6f 0d 00 00 0a 28 01 00 00 2b 0d 2b 00 09 2a } //01 00 
		$a_01_3 = {47 65 74 4d 65 74 68 6f 64 } //01 00  GetMethod
		$a_01_4 = {47 65 74 54 79 70 65 } //00 00  GetType
	condition:
		any of ($a_*)
 
}