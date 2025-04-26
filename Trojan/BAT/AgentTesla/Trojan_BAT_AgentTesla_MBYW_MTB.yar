
rule Trojan_BAT_AgentTesla_MBYW_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.MBYW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0d 07 06 91 11 [0-03] 61 07 06 17 58 08 5d 91 59 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}