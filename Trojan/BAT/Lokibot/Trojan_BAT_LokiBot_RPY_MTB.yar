
rule Trojan_BAT_LokiBot_RPY_MTB{
	meta:
		description = "Trojan:BAT/LokiBot.RPY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {07 11 06 91 11 08 61 07 11 06 17 58 08 5d 91 59 11 09 58 11 09 17 59 5f 13 0a 07 11 06 11 0a d2 9c 00 11 06 17 58 13 06 11 06 08 fe 04 13 0b 11 0b 2d a7 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule Trojan_BAT_LokiBot_RPY_MTB_2{
	meta:
		description = "Trojan:BAT/LokiBot.RPY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {00 11 05 09 5d 13 08 11 05 09 5b 13 09 08 11 08 11 09 6f 82 00 00 0a 13 0a 07 12 0a 28 83 00 00 0a 6f 84 00 00 0a 00 11 05 17 58 13 05 00 11 05 09 11 04 5a fe 04 13 0b 11 0b 2d c4 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule Trojan_BAT_LokiBot_RPY_MTB_3{
	meta:
		description = "Trojan:BAT/LokiBot.RPY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {13 1d 1f 1e 8d 2a 00 00 01 25 16 72 b0 e3 02 70 a2 25 17 07 a2 25 18 08 a2 25 19 09 a2 25 1a 11 04 a2 25 1b 11 05 a2 25 1c 11 06 a2 25 1d 11 07 a2 25 1e 11 08 a2 25 1f 09 11 09 a2 25 1f 0a 11 0a a2 25 1f 0b 11 0b a2 25 1f 0c 11 0c a2 25 1f 0d 11 0d a2 25 1f 0e 11 0e a2 25 1f 0f 11 0f a2 25 1f 10 11 10 a2 25 1f 11 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}