
rule Trojan_BAT_AgentTesla_JSB_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.JSB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {09 11 04 9a 13 05 11 05 28 ?? ?? ?? 0a 23 ?? ?? ?? ?? ?? ?? ?? ?? 59 28 ?? ?? ?? 0a b7 13 06 07 11 06 28 [0-15] 0a 0b 00 11 04 17 d6 13 04 11 04 09 8e 69 fe 04 13 07 11 07 2d ba } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}