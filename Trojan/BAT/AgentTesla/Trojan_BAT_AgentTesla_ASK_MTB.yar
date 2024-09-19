
rule Trojan_BAT_AgentTesla_ASK_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.ASK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {06 91 03 06 0e 04 8e 69 5d 91 61 d2 9c 00 06 17 58 0a } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}