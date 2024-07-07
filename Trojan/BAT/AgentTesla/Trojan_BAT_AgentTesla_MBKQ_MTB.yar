
rule Trojan_BAT_AgentTesla_MBKQ_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.MBKQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {07 08 18 5b 02 08 18 6f 90 01 01 00 00 0a 1f 10 28 90 01 01 00 00 0a 9c 00 08 18 58 0c 08 06 fe 04 0d 09 2d de 90 00 } //1
		$a_01_1 = {47 69 61 6f 44 69 65 6e } //1 GiaoDien
		$a_01_2 = {5a 00 33 00 5a 00 5a 00 45 00 32 00 5a 00 5a 00 31 00 33 00 5a 00 5a 00 45 00 32 00 5a 00 5a 00 31 00 33 00 5a 00 5a 00 45 00 32 00 5a 00 5a 00 31 00 33 00 5a 00 5a 00 } //1 Z3ZZE2ZZ13ZZE2ZZ13ZZE2ZZ13ZZ
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}