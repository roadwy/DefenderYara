
rule Trojan_BAT_AgentTesla_NZI_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NZI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {34 44 26 35 41 26 39 30 7e 26 30 33 7e 7e 7e 26 30 34 7e 7e 7e 26 46 46 26 46 46 7e 7e 26 42 38 7e 7e 7e 7e 7e 7e 7e 26 34 30 7e 7e 7e 7e 7e 7e 7e 7e 7e 7e 7e 7e 7e 7e 7e 7e 7e 7e 7e 7e 7e 7e 7e 7e 7e } //1 4D&5A&90~&03~~~&04~~~&FF&FF~~&B8~~~~~~~&40~~~~~~~~~~~~~~~~~~~~~~~~~
		$a_01_1 = {33 26 46 37 26 33 35 26 46 32 26 33 41 26 42 44 26 42 42 26 44 32 26 44 37 26 32 41 26 39 31 26 44 33 26 38 36 26 45 42 26 34 38 26 42 38 7e 7e 7e 7e 7e 7e 7e 7e 26 34 39 26 33 39 26 34 30 26 30 38 26 } //1 3&F7&35&F2&3A&BD&BB&D2&D7&2A&91&D3&86&EB&48&B8~~~~~~~~&49&39&40&08&
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}