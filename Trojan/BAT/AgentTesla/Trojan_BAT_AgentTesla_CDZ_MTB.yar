
rule Trojan_BAT_AgentTesla_CDZ_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.CDZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {07 11 05 28 ?? ?? ?? 0a 09 11 05 09 6f ?? ?? ?? 0a 5d 17 d6 28 ?? ?? ?? 0a da 13 06 08 11 06 28 ?? ?? ?? 0a 28 ?? ?? ?? 0a 28 ?? ?? ?? 0a 0c 11 05 17 d6 13 05 11 05 11 04 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}