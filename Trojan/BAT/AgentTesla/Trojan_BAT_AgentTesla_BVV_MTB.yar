
rule Trojan_BAT_AgentTesla_BVV_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.BVV!MTB,SIGNATURE_TYPE_PEHSTR,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_01_0 = {20 c8 00 00 00 da 1f 64 da 1f 1e d6 20 90 01 00 00 da } //10
	condition:
		((#a_01_0  & 1)*10) >=10
 
}