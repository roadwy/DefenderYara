
rule Trojan_BAT_AgentTesla_JD_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.JD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {11 05 11 0a 94 13 0b 11 04 11 0a 11 04 8e 69 5d 91 13 0c 11 06 11 0a 11 0b 11 0c 61 9e } //2
		$a_01_1 = {11 0a 17 58 13 0a 11 0a 11 05 8e 69 } //2
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2) >=4
 
}