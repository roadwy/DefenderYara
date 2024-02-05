
rule Trojan_BAT_LokiBot_OR_MTB{
	meta:
		description = "Trojan:BAT/LokiBot.OR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0a 00 03 00 00 0a 00 "
		
	strings :
		$a_03_0 = {70 03 09 18 6f 90 01 03 0a 28 90 01 03 0a 28 90 01 03 0a 04 07 6f 90 01 03 0a 28 90 01 03 0a 6a 61 b7 28 90 01 03 0a 28 90 01 03 0a 13 04 06 11 04 6f 90 01 03 0a 26 07 04 6f 90 01 03 0a 17 da 33 04 16 0b 2b 04 07 17 d6 0b 09 18 d6 0d 09 08 31 aa 90 00 } //01 00 
		$a_80_1 = {58 4f 52 5f 44 65 63 72 79 70 74 } //XOR_Decrypt  01 00 
		$a_80_2 = {73 61 64 61 64 61 } //sadada  00 00 
	condition:
		any of ($a_*)
 
}