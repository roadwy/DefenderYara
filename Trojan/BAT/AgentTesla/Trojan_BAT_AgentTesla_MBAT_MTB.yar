
rule Trojan_BAT_AgentTesla_MBAT_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.MBAT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 06 00 00 "
		
	strings :
		$a_01_0 = {34 44 7e 35 41 7e 39 30 4f 7e 30 33 4f 4f 4f 7e 30 34 4f 4f 4f 7e 46 46 7e 46 46 4f 4f 7e 42 } //2 4D~5A~90O~03OOO~04OOO~FF~FFOO~B
		$a_01_1 = {74 00 72 00 69 00 6e 00 67 00 31 00 00 00 00 00 01 fb e6 09 34 44 7e 35 41 7e 39 30 4f 7e 30 } //2
		$a_01_2 = {7e 31 46 7e 42 41 7e 30 45 4f 7e 42 34 7e 30 39 7e 43 44 7e 32 31 7e 42 38 7e 30 31 7e 34 43 } //2 ~1F~BA~0EO~B4~09~CD~21~B8~01~4C
		$a_01_3 = {4f 4f 4f 7e 34 30 7e 30 31 4f 7e 30 43 4f 4f 4f 4f 4f 4f 4f 4f 4f 4f 4f 4f 4f 4f 4f 4f 4f 4f } //2 OOO~40~01O~0COOOOOOOOOOOOOOOOOO
		$a_01_4 = {52 65 70 6c 61 63 65 } //1 Replace
		$a_01_5 = {53 70 6c 69 74 } //1 Split
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=10
 
}