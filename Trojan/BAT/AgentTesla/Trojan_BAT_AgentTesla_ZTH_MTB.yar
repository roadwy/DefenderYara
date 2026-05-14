
rule Trojan_BAT_AgentTesla_ZTH_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.ZTH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {02 03 04 6f ?? 00 00 0a 0a 12 00 28 ?? 00 00 0a 0b 07 05 61 d2 0b 07 05 61 d2 0b 07 2a } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}