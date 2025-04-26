
rule Trojan_BAT_AgentTesla_RDI_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.RDI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {72 02 7b 03 ?? ?? ?? 04 02 7b ?? ?? ?? ?? 6f ?? ?? ?? ?? 5d 6f ?? ?? ?? ?? 03 61 d2 2a } //2
		$a_01_1 = {4b 00 61 00 6d 00 70 00 66 00 } //1 Kampf
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}