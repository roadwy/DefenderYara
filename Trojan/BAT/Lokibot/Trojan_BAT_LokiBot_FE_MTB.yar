
rule Trojan_BAT_LokiBot_FE_MTB{
	meta:
		description = "Trojan:BAT/LokiBot.FE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 06 00 00 0a 00 "
		
	strings :
		$a_03_0 = {08 09 16 20 00 10 00 00 6f 90 01 03 0a 13 05 11 05 16 fe 02 13 06 11 06 2c 0e 00 11 04 09 16 11 05 6f 90 01 03 0a 00 00 00 11 05 16 fe 02 13 07 11 07 2d cb 90 00 } //01 00 
		$a_01_1 = {57 9d b6 29 09 0b 00 00 00 fa 01 33 00 16 00 00 01 00 00 00 98 00 00 00 37 } //01 00 
		$a_01_2 = {47 5a 69 70 53 74 72 65 61 6d } //01 00  GZipStream
		$a_01_3 = {47 65 74 54 79 70 65 73 } //01 00  GetTypes
		$a_01_4 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //01 00  CreateInstance
		$a_01_5 = {4d 65 6d 6f 72 79 53 74 72 65 61 6d } //00 00  MemoryStream
	condition:
		any of ($a_*)
 
}