
rule Trojan_BAT_Crysan_AAJE_MTB{
	meta:
		description = "Trojan:BAT/Crysan.AAJE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_03_0 = {0a 0c 07 16 28 ?? 00 00 0a 0d 08 07 1a 07 8e 69 1a da 6f ?? 00 00 0a 00 09 17 da 17 d6 8d ?? 00 00 01 13 04 08 16 6a 6f ?? 00 00 0a 00 00 08 16 73 ?? 00 00 0a 13 05 11 05 11 04 16 11 04 8e 69 6f ?? 00 00 0a 26 de 0e 00 11 05 2c 08 11 05 6f ?? 00 00 0a 00 dc 28 ?? 00 00 0a 11 04 16 11 04 8e 69 6f ?? 00 00 0a 0a de 0c } //4
		$a_01_1 = {74 00 6e 00 69 00 6f 00 70 00 79 00 72 00 74 00 6e 00 45 00 } //1 tniopyrtnE
		$a_01_2 = {65 00 6b 00 6f 00 76 00 6e 00 49 00 } //1 ekovnI
	condition:
		((#a_03_0  & 1)*4+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=6
 
}