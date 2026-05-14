
rule Trojan_BAT_Jalapeno_LMB_MTB{
	meta:
		description = "Trojan:BAT/Jalapeno.LMB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,23 00 23 00 02 00 00 "
		
	strings :
		$a_01_0 = {28 0c 00 00 0a 28 0d 00 00 0a 8c 11 00 00 01 72 01 00 00 70 28 0e 00 00 0a 28 0f 00 00 0a 0a 06 73 10 00 00 0a 0b 07 72 0b 00 00 70 28 11 00 00 0a 73 12 00 00 0a 72 43 00 00 70 6f 13 00 00 0a 6f 14 00 00 0a de 0a } //20
		$a_01_1 = {13 04 72 57 00 00 70 73 10 00 00 0a 13 05 11 05 11 04 6f 22 00 00 0a 6f 14 00 00 0a de 0c 11 05 2c 07 11 05 6f 15 00 00 0a dc } //15
	condition:
		((#a_01_0  & 1)*20+(#a_01_1  & 1)*15) >=35
 
}