
rule Trojan_BAT_AgentTesla_PTCW_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.PTCW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {38 ac ff ff ff 12 01 28 90 01 01 00 00 06 7d 0c 00 00 04 90 00 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}