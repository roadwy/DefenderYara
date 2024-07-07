
rule Trojan_BAT_AgentTesla_PSYM_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.PSYM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {26 06 72 4d 01 00 70 28 90 01 01 00 00 0a 6f 90 01 01 00 00 0a 06 6f 90 01 01 00 00 0a 02 16 02 8e 69 6f 90 01 01 00 00 0a 2a 90 00 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}