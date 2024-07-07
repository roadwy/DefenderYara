
rule Trojan_BAT_AgentTesla_MVF_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.MVF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {08 11 0a 11 0c 20 00 01 00 00 5d d2 9c } //1
		$a_00_1 = {47 72 6f 77 53 65 72 76 69 63 65 73 } //1 GrowServices
	condition:
		((#a_01_0  & 1)*1+(#a_00_1  & 1)*1) >=2
 
}