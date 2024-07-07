
rule Trojan_BAT_AgentTesla_ASFX_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.ASFX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {07 11 06 07 8e 69 6a 5d d4 91 08 11 06 08 8e 69 6a 5d d4 91 61 07 11 06 17 6a 58 07 8e 69 6a 5d d4 91 59 20 00 01 00 00 58 13 07 } //1
		$a_01_1 = {07 11 06 07 8e 69 6a 5d d4 11 07 20 00 01 00 00 5d d2 9c } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}