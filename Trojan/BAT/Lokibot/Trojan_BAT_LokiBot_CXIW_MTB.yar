
rule Trojan_BAT_LokiBot_CXIW_MTB{
	meta:
		description = "Trojan:BAT/LokiBot.CXIW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {0a 00 00 f5 4c 6b 51 24 d1 b0 88 eb 94 05 4f 4d df d9 6c 84 2c b0 ce 39 b3 87 9c 21 00 2e 68 19 } //01 00 
		$a_01_1 = {5a 57 4d 32 4d 7a 4a 6d 5a 44 6b 74 4d 54 59 35 4e 43 30 30 5a 6a 52 68 4c 54 6c 69 5a 6d 59 74 5a 6a 49 77 4e 6a 41 77 5a 54 4d 33 4f 54 67 78 } //01 00 
		$a_01_2 = {50 6f 77 65 72 65 64 20 62 79 20 53 6d 61 72 74 41 73 73 65 6d 62 6c 79 } //01 00 
		$a_01_3 = {51 00 6e 00 64 00 72 00 65 00 58 00 70 00 6c 00 65 00 6e 00 45 00 6c 00 } //01 00 
		$a_01_4 = {42 00 77 00 6b 00 79 00 7a 00 65 00 7a 00 71 00 25 00 } //00 00 
	condition:
		any of ($a_*)
 
}