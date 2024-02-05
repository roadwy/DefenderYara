
rule Trojan_BAT_LokiBot_RPE_MTB{
	meta:
		description = "Trojan:BAT/LokiBot.RPE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {1f 11 0d 09 18 d8 0d 09 20 a0 86 01 00 fe 02 13 04 11 04 2c 13 09 6c 23 00 00 00 00 00 6a e8 40 5b 28 54 00 00 0a b7 0d } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_LokiBot_RPE_MTB_2{
	meta:
		description = "Trojan:BAT/LokiBot.RPE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_00_0 = {00 06 07 06 6f e6 00 00 0a 5d 6f b0 01 00 0a 28 59 03 00 06 07 91 73 80 02 00 0a 0c 28 59 03 00 06 07 08 6f 81 02 00 0a 08 6f 82 02 00 0a 61 28 83 02 00 0a 9c 00 07 17 58 0b 07 28 59 03 00 06 8e 69 fe 04 0d 09 2d b8 } //01 00 
		$a_01_1 = {53 00 53 00 51 00 4a 00 52 00 53 00 57 00 59 00 49 00 48 00 54 00 57 00 51 00 41 00 58 00 } //00 00 
	condition:
		any of ($a_*)
 
}