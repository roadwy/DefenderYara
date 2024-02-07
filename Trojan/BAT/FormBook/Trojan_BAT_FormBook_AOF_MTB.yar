
rule Trojan_BAT_FormBook_AOF_MTB{
	meta:
		description = "Trojan:BAT/FormBook.AOF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_01_0 = {25 16 11 04 a2 25 17 7e 17 00 00 0a a2 25 18 11 01 a2 25 19 17 8c } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_FormBook_AOF_MTB_2{
	meta:
		description = "Trojan:BAT/FormBook.AOF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 02 00 "
		
	strings :
		$a_03_0 = {7b 2a 00 00 04 72 92 07 00 70 6f 90 01 03 0a 00 02 7b 2a 00 00 04 16 6f 90 01 03 0a 00 73 7f 00 00 0a 0b 06 72 bc 07 00 70 6f 90 01 03 0a 74 02 00 00 1b 0c 08 90 00 } //01 00 
		$a_01_1 = {50 00 72 00 6f 00 76 00 61 00 } //00 00  Prova
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_FormBook_AOF_MTB_3{
	meta:
		description = "Trojan:BAT/FormBook.AOF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 02 00 "
		
	strings :
		$a_03_0 = {0d 16 25 2d 1f 0a 2b 1b 13 04 1d 2c a9 2b c1 09 06 91 13 05 08 11 05 6f 90 01 03 0a 06 17 58 16 2d f0 0a 06 09 8e 69 32 e6 08 90 00 } //01 00 
		$a_01_1 = {46 00 72 00 6f 00 6d 00 42 00 61 00 73 00 65 00 36 00 34 00 53 00 74 00 72 00 69 00 6e 00 67 00 } //00 00  FromBase64String
	condition:
		any of ($a_*)
 
}