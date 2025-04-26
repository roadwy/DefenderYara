
rule Trojan_BAT_AgentTesla_R_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.R!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {b5 13 04 17 0c 2b 25 07 09 02 08 17 28 ?? ?? ?? ?? 28 ?? ?? ?? ?? 61 28 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_BAT_AgentTesla_R_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.R!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {01 25 16 28 ?? ?? ?? 06 9d 25 17 28 ?? ?? ?? 06 9d 25 28 ?? ?? ?? 06 73 ?? ?? ?? 0a [0-40] 2a } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}