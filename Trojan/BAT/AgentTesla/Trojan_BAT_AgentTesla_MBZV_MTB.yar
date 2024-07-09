
rule Trojan_BAT_AgentTesla_MBZV_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.MBZV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {d4 91 61 06 11 ?? 11 ?? 6a 5d d4 91 28 ?? 00 00 0a } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}