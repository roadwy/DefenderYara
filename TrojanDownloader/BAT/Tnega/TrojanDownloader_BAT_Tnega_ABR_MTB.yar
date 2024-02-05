
rule TrojanDownloader_BAT_Tnega_ABR_MTB{
	meta:
		description = "TrojanDownloader:BAT/Tnega.ABR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 04 00 00 05 00 "
		
	strings :
		$a_03_0 = {0c 07 08 07 6f 90 01 03 0a 1e 5b 6f 90 01 03 0a 6f 90 01 03 0a 07 08 07 6f 90 01 03 0a 1e 5b 6f 90 01 03 0a 6f 90 01 03 0a 2b 07 6f 90 01 03 0a 2b b0 07 17 6f 90 01 03 0a 2b 07 6f 90 01 03 0a 2b 98 06 07 6f 90 01 03 0a 17 73 90 01 03 0a 0d 09 02 16 02 8e 69 6f 90 01 03 0a de 0a 09 2c 06 09 6f 90 01 03 0a dc 06 6f 90 01 03 0a 13 04 de 14 90 00 } //01 00 
		$a_01_1 = {44 6f 77 6e 6c 6f 61 64 44 61 74 61 } //01 00 
		$a_01_2 = {4d 65 6d 6f 72 79 53 74 72 65 61 6d } //01 00 
		$a_01_3 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //00 00 
	condition:
		any of ($a_*)
 
}