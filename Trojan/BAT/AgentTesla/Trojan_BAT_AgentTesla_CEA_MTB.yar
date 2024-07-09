
rule Trojan_BAT_AgentTesla_CEA_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.CEA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {06 11 04 28 ?? ?? ?? 0a 08 11 04 08 6f ?? ?? ?? 0a 5d 17 d6 28 ?? ?? ?? 0a da 13 05 07 11 05 28 ?? ?? ?? 0a 28 ?? ?? ?? 0a 28 ?? ?? ?? 0a 0b 11 04 17 d6 13 04 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}