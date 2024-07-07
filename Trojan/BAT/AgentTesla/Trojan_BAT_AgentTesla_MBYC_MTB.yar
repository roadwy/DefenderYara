
rule Trojan_BAT_AgentTesla_MBYC_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.MBYC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {08 17 58 09 5d 13 90 01 01 07 08 91 1f 90 01 01 8d 90 01 01 00 00 01 25 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}