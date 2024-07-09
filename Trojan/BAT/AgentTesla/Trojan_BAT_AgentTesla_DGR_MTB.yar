
rule Trojan_BAT_AgentTesla_DGR_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.DGR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {08 11 04 02 11 04 91 07 61 06 09 91 61 28 ?? ?? ?? 06 9c } //1
		$a_03_1 = {06 02 08 18 28 ?? ?? ?? 06 1f 10 28 ?? ?? ?? 0a 84 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}