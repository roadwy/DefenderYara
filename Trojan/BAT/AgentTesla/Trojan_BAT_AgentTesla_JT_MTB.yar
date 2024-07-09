
rule Trojan_BAT_AgentTesla_JT_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.JT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_03_0 = {11 04 18 6f ?? 00 00 0a 20 03 02 00 00 28 ?? 00 00 0a 13 06 } //2
		$a_03_1 = {70 20 00 01 00 00 14 14 17 8d ?? 00 00 01 25 16 } //2
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*2) >=4
 
}