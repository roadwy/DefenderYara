
rule Trojan_BAT_Tiny_AMCA_MTB{
	meta:
		description = "Trojan:BAT/Tiny.AMCA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 02 00 "
		
	strings :
		$a_03_0 = {16 2d f7 00 2b 57 72 90 01 01 90 01 01 90 01 01 70 2b 5a 2b 62 38 90 01 01 00 00 00 38 90 01 01 00 00 00 8e 69 38 90 01 01 00 00 00 16 38 90 01 01 00 00 00 2b 1e 2b 69 08 91 0d 17 2c 25 06 08 06 07 08 59 17 59 91 9c 06 07 08 59 17 59 09 9c 08 17 58 0c 08 07 15 2c f9 18 5b 1d 2c f4 1e 2c f5 32 d3 16 2d e2 06 13 04 de 42 90 00 } //01 00 
		$a_80_1 = {48 74 74 70 43 6c 69 65 6e 74 } //HttpClient  01 00 
		$a_80_2 = {47 65 74 42 79 74 65 41 72 72 61 79 41 73 79 6e 63 } //GetByteArrayAsync  01 00 
		$a_80_3 = {67 65 74 5f 52 65 73 75 6c 74 } //get_Result  00 00 
	condition:
		any of ($a_*)
 
}