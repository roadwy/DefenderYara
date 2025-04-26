
rule Trojan_BAT_AgentTesla_GHS_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.GHS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {11 13 11 15 18 6f ?? ?? ?? 0a 20 03 02 00 00 28 ?? ?? ?? 0a 13 17 11 14 11 17 6f ?? ?? ?? 0a 00 11 15 18 58 13 15 00 11 15 11 13 6f ?? ?? ?? 0a fe 04 13 18 11 18 2d c7 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}