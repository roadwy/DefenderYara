
rule Trojan_BAT_AgentTesla_MBCI_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.MBCI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {72 bb 03 00 70 6f ?? 00 00 0a 74 ?? 00 00 1b 0c 08 28 ?? 00 00 0a 07 08 6f ?? 00 00 0a 07 06 72 c7 03 00 70 6f ?? 00 00 0a 74 ?? 00 00 1b 6f ?? 00 00 0a 07 06 72 d3 03 00 70 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_BAT_AgentTesla_MBCI_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.MBCI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_01_0 = {55 00 36 00 44 00 52 00 65 00 4d 00 72 00 6f 00 36 00 45 00 77 00 4a 00 65 00 61 00 55 00 6a 00 35 00 6a 00 41 00 39 00 6e 00 30 00 31 00 42 00 6d 00 5a 00 62 00 44 00 63 00 7a 00 6b 00 69 00 5a 00 43 00 6b 00 32 00 79 } //1
		$a_01_1 = {5a 00 35 00 39 00 5a 00 31 00 33 00 40 00 34 00 5a 00 32 00 42 00 5a 00 42 00 30 00 5a 00 31 00 36 00 40 00 41 00 5a 00 31 00 38 00 5a 00 31 00 33 00 40 00 34 00 5a 00 32 00 42 00 5a 00 41 00 39 00 40 00 33 00 40 00 34 00 } //1 Z59Z13@4Z2BZB0Z16@AZ18Z13@4Z2BZA9@3@4
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=1
 
}