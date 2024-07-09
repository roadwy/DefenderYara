
rule Trojan_BAT_AgentTesla_MBYC_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.MBYC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {08 17 58 09 5d 13 ?? 07 08 91 1f ?? 8d ?? 00 00 01 25 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}