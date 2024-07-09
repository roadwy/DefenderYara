
rule Trojan_BAT_AgentTesla_SSPP_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.SSPP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {13 04 09 73 ?? ?? ?? 0a 13 05 11 05 08 16 73 ?? ?? ?? 0a 13 06 11 06 11 04 6f ?? ?? ?? 0a 11 04 6f ?? ?? ?? 0a 0a de 2e } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}