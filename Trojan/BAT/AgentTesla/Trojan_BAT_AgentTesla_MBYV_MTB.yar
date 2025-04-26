
rule Trojan_BAT_AgentTesla_MBYV_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.MBYV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {61 07 11 06 17 58 08 5d 91 59 11 ?? 58 11 ?? 17 59 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}