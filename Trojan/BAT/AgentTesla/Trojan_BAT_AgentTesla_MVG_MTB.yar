
rule Trojan_BAT_AgentTesla_MVG_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.MVG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {06 07 06 8e 69 6a 5d d4 11 07 20 00 01 00 00 5d d2 9c } //1
		$a_00_1 = {70 72 6f 73 70 65 72 } //1 prosper
	condition:
		((#a_01_0  & 1)*1+(#a_00_1  & 1)*1) >=2
 
}