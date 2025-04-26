
rule Trojan_BAT_AgentTesla_KAAX_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.KAAX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {02 07 11 06 28 ?? 00 00 06 13 0b 02 11 09 11 0a 11 0b 28 ?? 00 00 06 13 0c 11 0e } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}