
rule Trojan_BAT_Injuke_AI_MTB{
	meta:
		description = "Trojan:BAT/Injuke.AI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {7e 73 00 00 04 06 7e 73 00 00 04 06 91 20 d6 02 00 00 59 d2 9c 00 06 17 58 0a 06 7e 73 00 00 04 8e 69 fe 04 0b 07 2d d7 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule Trojan_BAT_Injuke_AI_MTB_2{
	meta:
		description = "Trojan:BAT/Injuke.AI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {80 24 00 00 04 00 de 0b 06 2c 07 06 6f 2c 00 00 0a 00 dc 16 0c 2b 1b 00 7e 24 00 00 04 08 7e 24 00 00 04 08 91 20 4b 03 00 00 59 d2 9c 00 08 17 58 0c 08 7e 24 00 00 04 8e 69 fe 04 0d 09 2d d7 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule Trojan_BAT_Injuke_AI_MTB_3{
	meta:
		description = "Trojan:BAT/Injuke.AI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0d 09 16 04 a2 09 17 72 01 00 00 70 a2 09 18 28 90 01 03 0a a2 09 19 72 01 00 00 70 a2 09 1a 7e 11 00 00 04 a2 09 28 90 01 03 0a 0b 28 90 01 03 0a 07 6f 90 01 03 0a 0c 06 08 6f 90 01 03 0a 26 06 18 6f 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}