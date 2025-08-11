
rule Trojan_BAT_AgentTesla_SWE_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.SWE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {02 7b 01 00 00 04 6f ?? 00 00 0a 0a 06 8e 69 18 3c 01 00 00 00 2a 06 16 9a 75 03 00 00 01 0b 07 14 28 ?? 00 00 0a 39 01 00 00 00 2a 07 6f ?? 00 00 0a 7e 03 00 00 04 25 3a 17 00 00 00 26 7e 02 00 00 04 fe 06 0b 00 00 06 73 06 00 00 0a 25 80 03 00 00 04 28 ?? 00 00 2b 0c 08 14 28 ?? 00 00 0a 39 0c 00 00 00 02 7b 01 00 00 04 08 6f ?? 00 00 0a 2a } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}