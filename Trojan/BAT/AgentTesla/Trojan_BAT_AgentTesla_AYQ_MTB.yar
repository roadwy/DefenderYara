
rule Trojan_BAT_AgentTesla_AYQ_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.AYQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_02_0 = {91 08 61 07 11 07 91 61 b4 9c 11 07 03 ?? ?? ?? ?? ?? 17 da fe 01 13 08 11 08 13 09 11 09 2c 06 16 13 07 00 2b 08 00 11 07 17 d6 13 07 00 11 06 17 d6 13 06 11 06 11 05 31 c0 } //10
	condition:
		((#a_02_0  & 1)*10) >=10
 
}