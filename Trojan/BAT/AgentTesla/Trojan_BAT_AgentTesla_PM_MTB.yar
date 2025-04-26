
rule Trojan_BAT_AgentTesla_PM_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.PM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {0a 02 06 74 ?? ?? ?? ?? ?? ?? ?? ?? ?? 06 74 [0-0e] 25 2d 17 26 7e [0-0f] 25 [0-0f] 25 2d 17 26 7e [0-0f] 25 [0-0f] 2a } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}