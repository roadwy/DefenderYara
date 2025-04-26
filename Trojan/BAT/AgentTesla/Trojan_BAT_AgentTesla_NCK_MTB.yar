
rule Trojan_BAT_AgentTesla_NCK_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NCK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {00 02 17 da 17 d6 8d 01 00 00 01 0a 2b 00 06 2a } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}