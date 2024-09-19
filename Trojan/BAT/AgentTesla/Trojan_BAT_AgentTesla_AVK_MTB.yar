
rule Trojan_BAT_AgentTesla_AVK_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.AVK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {09 08 07 5d 07 58 07 5d 91 11 06 61 11 08 59 20 00 02 00 00 58 13 09 16 0a } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}