
rule TrojanDownloader_BAT_LokiBot_EW_MTB{
	meta:
		description = "TrojanDownloader:BAT/LokiBot.EW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {47 00 54 00 38 00 5a 00 5a 00 35 00 47 00 34 00 38 00 43 00 59 00 34 00 52 00 34 00 46 00 41 00 46 00 34 00 48 00 48 00 37 00 46 00 } //1 GT8ZZ5G48CY4R4FAF4HH7F
		$a_01_1 = {54 00 68 00 65 00 73 00 69 00 73 00 31 00 } //1 Thesis1
		$a_01_2 = {47 65 74 54 79 70 65 } //1 GetType
		$a_01_3 = {44 65 62 75 67 67 61 62 6c 65 41 74 74 72 69 62 75 74 65 } //1 DebuggableAttribute
		$a_01_4 = {44 65 62 75 67 67 69 6e 67 4d 6f 64 65 73 } //1 DebuggingModes
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}