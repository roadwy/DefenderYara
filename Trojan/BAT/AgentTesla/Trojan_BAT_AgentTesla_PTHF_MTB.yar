
rule Trojan_BAT_AgentTesla_PTHF_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.PTHF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {16 80 ef 01 00 04 28 90 01 01 03 00 06 28 90 01 01 04 00 0a 80 f0 01 00 04 2a 90 00 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}