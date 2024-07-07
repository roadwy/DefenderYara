
rule Trojan_BAT_Bandra_AMAB_MTB{
	meta:
		description = "Trojan:BAT/Bandra.AMAB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {00 06 07 02 07 6f 90 01 01 00 00 0a d2 9c 00 07 17 58 0b 07 06 8e 69 fe 04 0c 08 2d e5 90 00 } //1
		$a_01_1 = {00 09 11 07 02 11 04 07 58 17 58 91 06 61 d2 9c 11 04 07 17 58 58 13 04 00 11 07 17 58 13 07 11 07 09 8e 69 fe 04 13 08 11 08 2d d4 } //1
		$a_03_2 = {00 06 02 07 91 0c 12 02 28 90 01 01 00 00 0a 28 90 01 01 00 00 0a 0a 00 07 17 58 0b 07 02 8e 69 fe 04 0d 09 2d de 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}