
rule Trojan_BAT_LokiBot_RPR_MTB{
	meta:
		description = "Trojan:BAT/LokiBot.RPR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {d2 9c 00 09 17 58 0d 09 17 fe 04 13 04 11 04 2d c5 06 17 58 0a 00 08 17 58 0c 08 20 00 20 01 00 fe 04 13 05 11 05 2d a9 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_LokiBot_RPR_MTB_2{
	meta:
		description = "Trojan:BAT/LokiBot.RPR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {2b 25 2b 49 2b ec 2b 48 2b ee 2b 47 2b ef 2b 46 2b 47 2b 48 06 8e 69 5d 91 02 08 91 61 d2 90 01 05 08 17 58 0c 08 02 8e 69 32 e1 90 00 } //01 00 
		$a_01_1 = {64 00 65 00 73 00 63 00 61 00 74 00 61 00 6c 00 6f 00 67 00 61 00 6e 00 64 00 77 00 2e 00 74 00 6b 00 } //00 00  descatalogandw.tk
	condition:
		any of ($a_*)
 
}