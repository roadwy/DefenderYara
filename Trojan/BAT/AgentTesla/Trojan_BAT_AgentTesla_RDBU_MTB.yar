
rule Trojan_BAT_AgentTesla_RDBU_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.RDBU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {11 06 1f 16 5d 91 13 07 07 11 06 91 11 07 61 13 08 1f 66 13 10 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}