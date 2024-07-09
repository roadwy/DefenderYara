
rule Trojan_BAT_AgentTesla_PTHB_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.PTHB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {72 e6 09 00 70 28 ?? 02 00 06 26 02 28 ?? 02 00 06 0a 28 47 01 00 0a 06 16 06 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}