
rule TrojanDownloader_BAT_LokiBot_EX_MTB{
	meta:
		description = "TrojanDownloader:BAT/LokiBot.EX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {33 00 38 00 46 00 34 00 57 00 50 00 39 00 45 00 34 00 48 00 48 00 38 00 35 00 38 00 46 00 41 00 53 00 43 00 4a 00 53 00 42 00 35 00 } //01 00  38F4WP9E4HH858FASCJSB5
		$a_01_1 = {52 00 6f 00 73 00 74 00 69 00 73 00 61 00 } //01 00  Rostisa
		$a_01_2 = {47 65 74 54 79 70 65 } //01 00  GetType
		$a_01_3 = {44 65 62 75 67 67 61 62 6c 65 41 74 74 72 69 62 75 74 65 } //01 00  DebuggableAttribute
		$a_01_4 = {44 65 62 75 67 67 69 6e 67 4d 6f 64 65 73 } //00 00  DebuggingModes
	condition:
		any of ($a_*)
 
}