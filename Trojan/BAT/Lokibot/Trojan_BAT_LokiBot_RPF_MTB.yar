
rule Trojan_BAT_LokiBot_RPF_MTB{
	meta:
		description = "Trojan:BAT/LokiBot.RPF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {7e c0 00 00 04 20 00 00 00 00 97 29 50 00 00 11 00 06 fe 06 d6 01 00 06 73 b9 01 00 0a 28 2c 00 00 2b 28 2d 00 00 2b 0b 07 } //01 00 
		$a_01_1 = {4d 00 59 00 20 00 44 00 41 00 44 00 20 00 49 00 53 00 20 00 43 00 4f 00 4f 00 4c 00 } //01 00 
		$a_01_2 = {4e 00 75 00 6d 00 62 00 20 00 49 00 6e 00 20 00 54 00 68 00 65 00 20 00 45 00 6e 00 64 00 } //00 00 
	condition:
		any of ($a_*)
 
}