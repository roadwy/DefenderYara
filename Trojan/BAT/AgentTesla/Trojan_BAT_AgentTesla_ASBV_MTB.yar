
rule Trojan_BAT_AgentTesla_ASBV_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.ASBV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {11 09 11 0c 11 0e 58 17 58 17 59 11 0d 11 0f 58 17 58 17 59 6f 90 01 01 00 00 0a 13 10 12 10 28 90 01 01 00 00 0a 13 11 11 08 11 07 11 11 9c 11 07 17 58 13 07 11 0f 17 58 13 0f 00 11 0f 17 fe 04 13 12 11 12 2d bc 90 00 } //4
		$a_03_1 = {16 13 07 20 01 84 00 00 8d 90 01 01 00 00 01 13 08 11 06 72 90 00 } //1
	condition:
		((#a_03_0  & 1)*4+(#a_03_1  & 1)*1) >=5
 
}