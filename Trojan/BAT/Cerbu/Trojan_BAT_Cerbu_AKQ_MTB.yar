
rule Trojan_BAT_Cerbu_AKQ_MTB{
	meta:
		description = "Trojan:BAT/Cerbu.AKQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 01 00 00 "
		
	strings :
		$a_01_0 = {08 02 28 2e 00 00 0a 7e 08 00 00 04 15 16 28 2f 00 00 0a 16 9a 28 a7 01 00 06 28 37 00 00 0a de 0f 25 28 33 00 00 0a 13 04 28 34 00 00 0a de 00 02 28 2e 00 00 0a 7e 08 00 00 04 15 16 28 2f 00 00 0a 19 9a 28 35 00 00 0a 2c 18 08 1c 28 38 00 00 0a de 0f 25 28 33 00 00 0a 13 05 28 34 00 00 0a de 00 08 28 39 00 00 0a 26 de 0f } //3
	condition:
		((#a_01_0  & 1)*3) >=3
 
}