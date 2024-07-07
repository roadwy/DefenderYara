
rule Trojan_BAT_AgentTesla_RDAW_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.RDAW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {08 8e 69 6a 5d d4 91 61 28 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}