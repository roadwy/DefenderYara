
rule Trojan_BAT_LokiBot_ES_MTB{
	meta:
		description = "Trojan:BAT/LokiBot.ES!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 01 00 "
		
	strings :
		$a_01_0 = {24 64 32 37 63 62 37 62 64 2d 33 63 39 34 2d 34 34 65 36 2d 61 64 66 33 2d 38 63 65 65 31 35 61 36 34 61 32 63 } //01 00  $d27cb7bd-3c94-44e6-adf3-8cee15a64a2c
		$a_01_1 = {43 6f 6d 70 72 65 73 73 69 6f 6e 4d 6f 64 65 } //01 00  CompressionMode
		$a_01_2 = {47 5a 69 70 53 74 72 65 61 6d } //01 00  GZipStream
		$a_01_3 = {53 74 61 72 20 49 6e 74 65 72 69 6f 72 20 44 65 73 69 67 6e } //01 00  Star Interior Design
		$a_01_4 = {42 69 6e 61 72 79 46 69 6c 65 53 63 68 65 6d 61 } //01 00  BinaryFileSchema
		$a_01_5 = {67 65 74 5f 59 } //01 00  get_Y
		$a_01_6 = {67 65 74 5f 58 } //00 00  get_X
	condition:
		any of ($a_*)
 
}