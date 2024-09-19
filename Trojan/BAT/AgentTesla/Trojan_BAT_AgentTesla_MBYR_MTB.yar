
rule Trojan_BAT_AgentTesla_MBYR_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.MBYR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {91 11 06 61 13 ?? 11 ?? 17 58 08 5d } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}