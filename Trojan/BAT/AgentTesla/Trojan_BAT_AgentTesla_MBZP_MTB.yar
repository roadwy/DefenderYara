
rule Trojan_BAT_AgentTesla_MBZP_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.MBZP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {61 06 07 17 6a 58 11 ?? 6a 5d d4 91 28 ?? 00 00 0a 59 20 00 01 00 00 58 20 00 01 00 00 5d } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}