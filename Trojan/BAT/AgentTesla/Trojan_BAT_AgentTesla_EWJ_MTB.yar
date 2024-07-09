
rule Trojan_BAT_AgentTesla_EWJ_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.EWJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {08 11 06 17 da 6f ?? ?? ?? 0a 28 ?? ?? ?? 06 09 11 06 09 6f ?? ?? ?? 0a 5d 6f ?? ?? ?? 0a 28 ?? ?? ?? 06 da 13 07 11 04 11 07 28 ?? ?? ?? 06 28 ?? ?? ?? 0a 28 ?? ?? ?? 0a 13 04 11 06 17 d6 13 06 } //1
		$a_01_1 = {86 06 20 00 86 06 20 00 86 06 20 00 86 06 20 00 86 06 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}