
rule Trojan_BAT_AgentTesla_EDE_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.EDE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {06 02 08 23 00 00 00 00 00 00 10 40 28 ?? ?? ?? 06 b7 6f ?? ?? ?? 0a 23 00 00 00 00 00 00 70 40 28 ?? ?? ?? 06 b7 28 ?? ?? ?? 06 84 28 30 00 00 0a 6f ?? ?? ?? 0a 26 08 18 d6 0c 20 01 00 00 00 16 } //1
		$a_03_1 = {08 11 04 02 11 04 91 07 61 06 09 91 61 28 ?? ?? ?? 06 9c 09 03 28 ?? ?? ?? 06 17 59 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}