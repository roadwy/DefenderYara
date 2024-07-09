
rule Trojan_BAT_AgentTesla_BUS_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.BUS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {07 02 09 18 6f ?? ?? ?? 0a 1f 10 28 ?? ?? ?? 0a 84 28 ?? ?? ?? 0a 28 ?? ?? ?? 06 26 09 18 d6 0d 09 08 3e } //1
		$a_02_1 = {02 02 8e 69 17 da 91 1f 70 61 0c 02 8e 69 17 d6 17 da 17 d6 8d ?? ?? ?? 01 0d 02 8e 69 17 da } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}