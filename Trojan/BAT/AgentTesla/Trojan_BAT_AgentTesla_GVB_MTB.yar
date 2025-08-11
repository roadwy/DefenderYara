
rule Trojan_BAT_AgentTesla_GVB_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.GVB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {1f 61 6a 02 28 43 00 00 06 25 26 0a de 07 07 28 d9 01 00 06 dc 06 2a } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}