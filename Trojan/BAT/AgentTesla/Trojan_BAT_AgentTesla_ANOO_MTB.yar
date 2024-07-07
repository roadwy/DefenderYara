
rule Trojan_BAT_AgentTesla_ANOO_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.ANOO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {11 02 11 07 11 01 02 11 07 18 5a 18 6f } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}