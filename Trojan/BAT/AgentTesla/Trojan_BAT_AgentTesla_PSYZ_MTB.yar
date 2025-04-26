
rule Trojan_BAT_AgentTesla_PSYZ_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.PSYZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {09 11 04 07 11 04 91 06 59 d2 9c 11 04 17 58 13 04 11 04 07 8e 69 32 e8 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}