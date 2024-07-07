
rule Trojan_BAT_AgentTesla_RDAS_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.RDAS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {07 28 07 00 00 0a 07 28 08 00 00 0a 0d 07 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}