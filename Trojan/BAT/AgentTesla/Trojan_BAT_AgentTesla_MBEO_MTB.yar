
rule Trojan_BAT_AgentTesla_MBEO_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.MBEO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {11 0c 08 11 0a 91 61 07 11 0b 91 59 11 0d 58 11 0d 5d 13 0e 07 11 09 11 0e d2 9c 11 06 17 58 13 06 } //1
		$a_01_1 = {52 00 5a 00 50 00 34 00 34 00 38 00 52 00 4e 00 35 00 56 00 5a 00 35 00 41 00 47 00 43 00 38 00 37 00 35 00 37 00 35 00 35 00 32 00 } //1 RZP448RN5VZ5AGC8757552
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}