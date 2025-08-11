
rule Trojan_BAT_Crysan_BAB_MTB{
	meta:
		description = "Trojan:BAT/Crysan.BAB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {0a 73 56 00 00 0a 0b 1a 8d 06 00 00 01 0c 06 08 16 1a 6f 35 00 00 0a 1a 2e 06 73 5a 00 00 0a 7a 06 16 73 5b 00 00 0a 0d 09 07 6f 57 00 00 0a de 07 09 6f 59 00 00 0a dc 07 6f 58 00 00 0a 13 04 de 0e 07 6f 59 00 00 0a dc } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}
rule Trojan_BAT_Crysan_BAB_MTB_2{
	meta:
		description = "Trojan:BAT/Crysan.BAB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {11 02 11 01 6f 17 00 00 0a 38 00 00 00 00 11 02 6f 18 00 00 0a 13 03 38 0e 00 00 00 11 02 11 00 6f 19 00 00 0a 38 d6 ff ff ff 00 02 73 1a 00 00 0a 13 04 38 00 00 00 00 00 11 04 11 03 16 73 1b 00 00 0a 13 05 38 00 00 00 00 00 73 1c 00 00 0a 13 06 38 00 00 00 00 00 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}