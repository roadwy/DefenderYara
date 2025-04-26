
rule Trojan_BAT_AgentTesla_NTO_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NTO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {02 05 04 5d 91 03 05 1f 16 5d 28 ?? ?? ?? 06 61 28 ?? ?? ?? 06 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}