
rule Trojan_BAT_AgentTesla_PSYQ_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.PSYQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {6f 22 00 00 0a 9a 28 ?? 00 00 0a 13 0c 11 0c 73 21 00 00 0a 11 0c 8e 69 6f 22 00 00 0a 9a 11 0b 28 ?? 00 00 0a 13 0d 72 66 8b 09 70 1e 28 ?? 00 00 06 72 6a 8b 09 70 28 ?? 00 00 0a 13 0e 11 0e 11 0d 28 ?? 00 00 0a 11 08 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}