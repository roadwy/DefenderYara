
rule Trojan_BAT_LokiBot_FC_MTB{
	meta:
		description = "Trojan:BAT/LokiBot.FC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {02 03 17 58 7e 90 01 03 04 5d 91 0a 16 0b 17 0c 00 02 03 28 90 01 03 06 0d 06 04 58 13 04 09 11 04 59 04 5d 0b 00 02 03 7e 90 01 03 04 5d 07 d2 9c 02 13 05 2b 00 11 05 2a 90 00 } //01 00 
		$a_01_1 = {47 65 74 4d 65 74 68 6f 64 } //01 00 
		$a_01_2 = {67 65 74 5f 41 73 73 65 6d 62 6c 79 } //00 00 
	condition:
		any of ($a_*)
 
}