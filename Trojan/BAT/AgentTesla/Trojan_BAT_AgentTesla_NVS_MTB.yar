
rule Trojan_BAT_AgentTesla_NVS_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NVS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {11 02 11 04 02 11 04 91 11 01 61 11 08 11 03 91 61 } //1
		$a_01_1 = {36 39 65 37 63 61 32 65 65 65 31 35 } //1 69e7ca2eee15
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}