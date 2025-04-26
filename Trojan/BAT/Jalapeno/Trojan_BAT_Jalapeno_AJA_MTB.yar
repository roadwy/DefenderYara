
rule Trojan_BAT_Jalapeno_AJA_MTB{
	meta:
		description = "Trojan:BAT/Jalapeno.AJA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_01_0 = {16 13 07 2b 12 00 11 06 11 07 58 05 11 07 91 52 00 11 07 17 58 13 07 11 07 05 8e 69 fe 04 13 08 11 08 2d e1 } //3
		$a_01_1 = {16 13 09 2b 24 00 06 11 07 11 09 58 91 07 11 09 91 fe 01 16 fe 01 13 0a 11 0a 2c 06 00 16 13 08 2b 14 00 11 09 17 58 13 09 11 09 07 8e 69 fe 04 13 0b 11 0b 2d cf 11 08 13 0c 11 0c 2c 0b 00 08 11 07 } //2
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*2) >=5
 
}