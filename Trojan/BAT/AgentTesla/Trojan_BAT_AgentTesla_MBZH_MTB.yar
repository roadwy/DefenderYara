
rule Trojan_BAT_AgentTesla_MBZH_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.MBZH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {5d d4 07 11 ?? 07 8e 69 6a 5d d4 91 08 11 ?? 69 6f ?? ?? ?? 0a 61 07 11 ?? 17 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}