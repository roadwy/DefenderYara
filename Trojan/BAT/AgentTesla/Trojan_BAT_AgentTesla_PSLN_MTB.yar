
rule Trojan_BAT_AgentTesla_PSLN_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.PSLN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {6f 8b 00 00 0a 6f 90 01 03 0a 13 04 73 90 01 03 0a 13 05 11 05 11 04 6f 90 01 03 0a 11 05 18 6f 90 01 03 0a 11 05 18 6f 90 01 03 0a 11 05 6f 90 01 03 0a 13 06 11 06 07 16 07 8e 69 6f 90 01 03 0a 13 07 28 90 01 03 0a 11 07 6f 90 01 03 0a 13 08 11 08 6f 90 01 03 0a 13 0a de 4f 02 38 5e ff ff ff 28 69 00 00 06 38 63 ff ff ff 6f 90 01 03 0a 38 5f ff ff ff 0a 38 5e ff ff ff 06 38 5d ff ff ff 28 79 00 00 0a 90 00 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}