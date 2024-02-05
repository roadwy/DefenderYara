
rule TrojanDownloader_BAT_SmokeLoader_B_MTB{
	meta:
		description = "TrojanDownloader:BAT/SmokeLoader.B!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {00 25 17 2b 22 00 25 17 2b 24 00 25 14 2b 26 00 2b 2a 20 20 4e 00 00 2b 2a 26 00 1a 2c cf de } //01 00 
		$a_01_1 = {00 73 16 00 00 0a 0c 00 2b 31 16 2b 31 2b 36 2b 3b 00 09 08 6f 17 00 00 0a 00 00 de 11 } //01 00 
		$a_01_2 = {70 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 } //01 00 
		$a_01_3 = {47 5a 69 70 53 74 72 65 61 6d } //01 00 
		$a_01_4 = {54 6f 41 72 72 61 79 } //00 00 
	condition:
		any of ($a_*)
 
}