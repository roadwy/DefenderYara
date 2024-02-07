
rule Trojan_BAT_LokiBot_AQE_MTB{
	meta:
		description = "Trojan:BAT/LokiBot.AQE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0d 00 06 00 00 0a 00 "
		
	strings :
		$a_03_0 = {16 9a 14 19 8d 90 01 03 01 25 16 28 90 01 03 06 a2 25 17 28 90 01 03 06 a2 25 18 90 01 05 28 90 01 03 06 a2 14 6f 90 01 03 0a 20 00 08 00 00 2a 90 00 } //01 00 
		$a_80_1 = {47 65 74 54 79 70 65 } //GetType  01 00 
		$a_80_2 = {47 65 74 4d 65 74 68 6f 64 } //GetMethod  01 00 
		$a_80_3 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //CreateInstance  01 00 
		$a_80_4 = {54 6f 41 72 72 61 79 } //ToArray  01 00 
		$a_81_5 = {54 6f 49 6e 74 33 32 } //00 00  ToInt32
	condition:
		any of ($a_*)
 
}