
rule Trojan_BAT_AgentTesla_SPVB_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.SPVB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {07 08 94 0d 00 06 03 09 59 d1 13 04 12 04 28 ?? ?? ?? 0a 28 ?? ?? ?? 0a 0a 00 08 17 58 0c 08 07 8e 69 32 dc } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}