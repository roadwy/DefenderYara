
rule Trojan_BAT_LokiBot_RDB_MTB{
	meta:
		description = "Trojan:BAT/LokiBot.RDB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {46 72 6f 6d 42 61 73 65 36 34 } //01 00  FromBase64
		$a_01_1 = {47 5a 69 70 53 74 72 65 61 6d } //02 00  GZipStream
		$a_01_2 = {11 00 2a 00 28 26 00 00 0a 02 6f 27 00 00 0a 13 00 } //02 00 
		$a_03_3 = {11 01 14 14 6f 1e 00 00 0a 26 38 90 01 04 11 00 6f 24 00 00 0a 1b 9a 13 01 90 00 } //02 00 
		$a_01_4 = {2a 00 02 74 25 00 00 01 6f 25 00 00 0a 1f 14 9a 13 00 } //00 00 
	condition:
		any of ($a_*)
 
}