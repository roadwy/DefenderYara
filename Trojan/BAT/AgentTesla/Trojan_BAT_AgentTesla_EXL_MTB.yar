
rule Trojan_BAT_AgentTesla_EXL_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.EXL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {00 00 04 03 04 5d 90 01 05 61 90 00 } //1
		$a_03_1 = {02 03 17 58 90 01 05 5d 91 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}