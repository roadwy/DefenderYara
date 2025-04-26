
rule Trojan_BAT_AgentTesla_JIZ_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.JIZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {08 07 09 07 18 d8 18 6f ?? ?? ?? 0a 1f 10 28 ?? ?? ?? 0a 9c 07 17 d6 0b 07 11 04 31 e3 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}