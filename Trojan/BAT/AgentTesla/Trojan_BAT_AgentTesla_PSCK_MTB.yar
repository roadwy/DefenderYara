
rule Trojan_BAT_AgentTesla_PSCK_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.PSCK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {72 5b 00 00 70 0a 06 28 7b 00 00 0a 25 26 0b 28 7c 00 00 0a 25 26 07 16 07 8e 69 6f 7d 00 00 0a 25 26 0a 28 2b 00 00 0a 25 26 06 6f 30 00 00 0a 25 26 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}