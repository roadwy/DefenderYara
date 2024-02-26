
rule Trojan_BAT_LokiBot_ASFO_MTB{
	meta:
		description = "Trojan:BAT/LokiBot.ASFO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {0a 06 18 5b 8d 90 01 01 00 00 01 0b 16 0c 2b 19 07 08 18 5b 02 08 18 6f 90 01 01 00 00 0a 1f 10 28 90 01 01 00 00 0a d2 9c 08 18 58 0c 08 06 fe 04 0d 09 2d 90 00 } //01 00 
		$a_01_1 = {44 4c 50 4b 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 } //00 00  DLPK.Properties.Resources
	condition:
		any of ($a_*)
 
}