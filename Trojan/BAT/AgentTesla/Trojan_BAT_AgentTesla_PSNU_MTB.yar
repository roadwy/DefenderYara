
rule Trojan_BAT_AgentTesla_PSNU_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.PSNU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {14 0a 38 18 00 00 00 00 02 72 01 00 00 70 28 03 00 00 06 0a dd 06 00 00 00 26 dd 00 00 00 00 06 2c e5 06 2a } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}