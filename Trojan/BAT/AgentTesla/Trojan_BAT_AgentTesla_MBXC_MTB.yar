
rule Trojan_BAT_AgentTesla_MBXC_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.MBXC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {07 09 91 11 ?? 61 07 09 17 58 08 5d 91 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}