
rule Trojan_BAT_LokiBot_CXJK_MTB{
	meta:
		description = "Trojan:BAT/LokiBot.CXJK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {08 11 0a 11 09 6f 90 01 04 13 0b 16 13 0c 11 05 11 08 9a 13 0e 11 0e 13 0d 11 0d 72 90 01 04 28 90 01 04 2d 1e 11 0d 72 90 01 04 28 90 01 04 2d 1b 11 0d 72 90 01 04 28 90 01 04 2d 18 2b 21 12 0b 28 90 01 04 13 0c 2b 16 12 0b 28 90 01 04 13 0c 2b 0b 12 0b 28 90 01 04 13 0c 2b 00 07 11 0c 6f 90 01 04 00 00 11 0a 17 58 13 0a 11 0a 09 fe 04 13 0f 11 0f 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_LokiBot_CXJK_MTB_2{
	meta:
		description = "Trojan:BAT/LokiBot.CXJK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {34 00 44 00 35 00 41 00 39 00 7c 00 7c 00 33 00 7c 00 7c 00 7c 00 30 00 34 00 7c 00 7c 00 7c 00 46 00 46 00 46 00 46 } //01 00 
		$a_01_1 = {45 00 31 00 46 00 42 00 41 00 30 00 45 00 7c 00 42 00 34 00 30 00 39 00 43 00 44 00 32 00 31 00 42 00 38 } //01 00 
		$a_01_2 = {7c 00 7c 00 30 00 41 00 36 00 46 00 31 00 7c 00 7c 00 7c 00 41 00 37 00 } //01 00  ||0A6F1|||A7
		$a_01_3 = {30 00 42 00 32 00 42 00 7c 00 31 00 31 00 30 00 42 00 32 00 41 00 7c 00 } //00 00  0B2B|110B2A|
	condition:
		any of ($a_*)
 
}