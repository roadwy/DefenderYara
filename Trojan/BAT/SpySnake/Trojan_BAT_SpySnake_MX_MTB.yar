
rule Trojan_BAT_SpySnake_MX_MTB{
	meta:
		description = "Trojan:BAT/SpySnake.MX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,10 00 10 00 04 00 00 0a 00 "
		
	strings :
		$a_03_0 = {08 11 07 07 11 07 9a 1f 10 28 90 01 03 0a d2 9c 11 07 17 58 13 07 11 07 07 8e 69 fe 04 13 08 11 08 2d dd 90 00 } //02 00 
		$a_01_1 = {54 00 68 00 69 00 73 00 20 00 61 00 70 00 70 00 6c 00 69 00 63 00 61 00 74 00 69 00 6f 00 6e 00 20 00 77 00 69 00 6c 00 6c 00 20 00 6b 00 69 00 6c 00 6c 00 20 00 61 00 6e 00 64 00 20 00 72 00 65 00 73 00 75 00 72 00 72 00 65 00 63 00 74 00 20 00 61 00 6e 00 79 00 20 00 61 00 63 00 74 00 69 00 76 00 65 00 20 00 6e 00 65 00 74 00 77 00 6f 00 72 00 6b 00 } //02 00  This application will kill and resurrect any active network
		$a_01_2 = {73 00 6e 00 61 00 70 00 73 00 68 00 6f 00 74 00 20 00 69 00 73 00 20 00 74 00 61 00 6b 00 65 00 6e 00 20 00 6f 00 74 00 20 00 74 00 68 00 65 00 20 00 63 00 6f 00 6e 00 6e 00 65 00 63 00 74 00 69 00 76 00 69 00 74 00 79 00 } //02 00  snapshot is taken ot the connectivity
		$a_01_3 = {4e 65 74 77 6f 72 6b 41 73 73 61 73 73 69 6e 2e 53 61 6d 70 6c 65 73 2e 43 6f 66 66 65 65 4d 61 6b 65 72 } //00 00  NetworkAssassin.Samples.CoffeeMaker
	condition:
		any of ($a_*)
 
}