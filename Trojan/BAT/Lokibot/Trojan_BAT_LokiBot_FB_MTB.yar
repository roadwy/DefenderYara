
rule Trojan_BAT_LokiBot_FB_MTB{
	meta:
		description = "Trojan:BAT/LokiBot.FB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {20 16 18 01 00 0c 2b 13 00 07 08 20 00 01 00 00 28 90 01 03 06 0b 00 08 15 58 0c 08 16 fe 04 16 fe 01 0d 09 2d e2 90 00 } //01 00 
		$a_01_1 = {47 65 74 4d 65 74 68 6f 64 } //01 00  GetMethod
		$a_01_2 = {67 65 74 5f 41 73 73 65 6d 62 6c 79 } //00 00  get_Assembly
	condition:
		any of ($a_*)
 
}