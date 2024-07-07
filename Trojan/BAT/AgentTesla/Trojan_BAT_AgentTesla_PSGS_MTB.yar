
rule Trojan_BAT_AgentTesla_PSGS_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.PSGS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {6f 1f 00 00 0a 26 07 08 6f 90 01 03 06 11 08 90 01 05 5a 20 ba e4 d8 4f 61 38 4d ff ff ff 06 6f 90 01 03 0a 13 07 20 81 6e fd d6 38 3b ff ff ff 09 11 07 d2 6e 1e 11 06 5a 1f 3f 5f 62 60 0d 11 08 20 46 0b 49 e7 5a 20 1a 0d ab de 61 38 19 ff ff ff 09 69 8d 76 00 00 01 25 17 73 90 01 03 0a 13 04 06 6f 90 01 03 0a 1f 0d 6a 59 13 05 07 06 11 04 11 05 09 6f 90 01 03 06 2a 90 00 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}