
rule Trojan_BAT_AgentTesla_DYB_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.DYB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {02 08 18 20 90 01 04 20 90 01 04 28 90 01 03 2b 1f 10 20 90 01 04 20 90 01 04 28 90 01 03 2b 84 90 01 04 28 90 01 03 06 6f 90 01 03 0a 26 90 00 } //1
		$a_03_1 = {08 11 04 02 11 04 91 07 61 06 75 90 01 03 1b 09 91 61 1f 48 1f 63 28 90 01 03 06 9c 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}
rule Trojan_BAT_AgentTesla_DYB_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.DYB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {09 06 8e 69 1e 5a 6f 90 01 03 0a 00 09 06 6f 90 01 03 0a 00 09 07 8e 69 1e 5a 6f 90 01 03 0a 00 09 07 6f 90 01 03 0a 00 09 6f 90 01 03 0a 13 04 00 03 73 90 01 03 0a 13 05 00 11 05 11 04 16 73 90 01 03 0a 13 06 00 03 8e 69 8d 90 01 03 01 13 07 11 06 11 07 16 03 8e 69 6f 90 01 03 0a 13 08 11 07 11 08 28 90 01 03 2b 28 90 01 03 2b 0c 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}