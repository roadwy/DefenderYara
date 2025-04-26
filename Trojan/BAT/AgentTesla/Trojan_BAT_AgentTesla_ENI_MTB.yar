
rule Trojan_BAT_AgentTesla_ENI_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.ENI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {02 02 8e 69 17 59 91 1f 70 61 13 01 } //1
		$a_01_1 = {02 11 09 91 11 01 61 11 00 11 03 91 61 13 05 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}