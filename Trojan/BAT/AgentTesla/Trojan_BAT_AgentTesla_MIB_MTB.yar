
rule Trojan_BAT_AgentTesla_MIB_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.MIB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {25 16 06 07 08 09 28 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? a2 28 ?? ?? ?? ?? ?? ?? ?? ?? ?? 13 04 11 04 72 ?? ?? ?? ?? ?? ?? ?? ?? ?? 13 05 11 05 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}