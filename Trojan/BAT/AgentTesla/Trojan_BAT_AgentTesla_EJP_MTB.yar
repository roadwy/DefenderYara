
rule Trojan_BAT_AgentTesla_EJP_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.EJP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {07 02 06 23 00 00 00 00 00 00 10 40 28 ?? ?? ?? 0a b7 6f ?? ?? ?? 0a 23 00 00 00 00 00 00 70 40 28 ?? ?? ?? 0a b7 28 ?? ?? ?? 0a 84 28 ?? ?? ?? 0a 13 05 12 05 28 ?? ?? ?? 0a 28 ?? ?? ?? 0a 0b 06 18 d6 0a } //1
		$a_01_1 = {02 07 91 11 04 61 09 06 91 61 13 05 08 07 11 05 d2 9c 06 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}