
rule Trojan_BAT_LokiBot_FL_MTB{
	meta:
		description = "Trojan:BAT/LokiBot.FL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 07 00 00 0a 00 "
		
	strings :
		$a_01_0 = {24 38 66 35 35 34 66 35 34 2d 65 66 39 33 2d 34 30 31 63 2d 61 37 34 66 2d 32 61 66 32 33 64 37 62 61 36 35 63 } //0a 00 
		$a_01_1 = {24 62 30 38 38 34 32 63 32 2d 31 30 35 63 2d 34 37 31 34 2d 61 36 62 35 2d 33 37 30 31 31 39 39 36 33 37 35 32 } //01 00 
		$a_01_2 = {4a 00 39 00 34 00 54 00 52 00 34 00 34 00 50 00 56 00 34 00 47 00 } //01 00 
		$a_01_3 = {52 00 5a 00 35 00 38 00 35 00 38 00 } //01 00 
		$a_01_4 = {50 00 6f 00 6b 00 65 00 42 00 61 00 6c 00 6c 00 } //01 00 
		$a_01_5 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //01 00 
		$a_01_6 = {41 63 74 69 76 61 74 6f 72 } //00 00 
	condition:
		any of ($a_*)
 
}