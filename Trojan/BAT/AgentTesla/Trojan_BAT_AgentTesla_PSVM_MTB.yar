
rule Trojan_BAT_AgentTesla_PSVM_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.PSVM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {02 28 14 00 00 0a 75 04 00 00 1b 0a 06 8e 69 8d 15 00 00 01 0b 16 0c 2b 1b 07 08 06 08 91 20 9a 84 00 00 28 ?? 01 00 06 28 ?? 00 00 0a 59 d2 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}