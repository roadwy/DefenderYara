
rule Trojan_BAT_AgentTesla_MBJX_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.MBJX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {09 11 05 06 11 05 91 08 61 07 11 04 91 61 d2 9c 11 04 1f 15 } //1
		$a_01_1 = {45 00 38 00 51 00 37 00 34 00 39 00 47 00 42 00 59 00 47 00 34 00 44 00 38 00 37 00 46 00 38 00 34 00 47 00 37 00 55 00 34 00 4a 00 } //1 E8Q749GBYG4D87F84G7U4J
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}