
rule Trojan_BAT_LokiBot_FF_MTB{
	meta:
		description = "Trojan:BAT/LokiBot.FF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 06 00 00 0a 00 "
		
	strings :
		$a_01_0 = {57 9f a2 29 09 03 00 00 00 00 00 00 00 00 00 00 01 00 00 00 86 00 00 00 3e } //01 00 
		$a_01_1 = {24 39 38 65 63 37 61 66 39 2d 62 66 61 64 2d 34 66 61 37 2d 61 62 39 62 2d 34 65 61 63 35 31 30 32 63 39 66 33 } //01 00  $98ec7af9-bfad-4fa7-ab9b-4eac5102c9f3
		$a_01_2 = {47 5a 69 70 53 74 72 65 61 6d } //01 00  GZipStream
		$a_01_3 = {47 65 74 54 79 70 65 73 } //01 00  GetTypes
		$a_01_4 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //01 00  CreateInstance
		$a_01_5 = {4d 65 6d 6f 72 79 53 74 72 65 61 6d } //00 00  MemoryStream
	condition:
		any of ($a_*)
 
}