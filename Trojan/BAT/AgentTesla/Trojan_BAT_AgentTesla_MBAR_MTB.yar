
rule Trojan_BAT_AgentTesla_MBAR_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.MBAR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {0c 16 13 07 2b 15 08 11 07 07 11 07 9a 1f 10 28 ?? 00 00 0a 9c 11 07 17 58 13 07 } //1
		$a_01_1 = {34 44 7e 35 41 7e 39 30 4f 7e 30 33 4f 4f 4f 7e 30 34 4f 4f 4f 7e 46 46 7e 46 46 4f 4f 7e 42 38 4f 4f 4f 4f 4f 4f 4f 7e 34 } //1 4D~5A~90O~03OOO~04OOO~FF~FFOO~B8OOOOOOO~4
		$a_01_2 = {46 57 53 46 44 57 } //1 FWSFDW
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}