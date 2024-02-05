
rule Trojan_BAT_AgentTesla_CSTU_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.CSTU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {72 a5 15 00 70 28 2f 01 00 0a 72 90 01 04 28 90 01 04 20 90 01 04 14 14 17 8d 01 00 00 01 25 16 7e 89 00 00 04 a2 6f 31 01 00 0a 26 2a 90 00 } //01 00 
		$a_01_1 = {51 00 45 00 73 00 73 00 44 00 4a 00 5a 00 68 00 51 00 6e 00 4c 00 79 00 77 00 44 00 6e 00 4a 00 47 00 70 00 42 00 45 00 72 00 } //00 00 
	condition:
		any of ($a_*)
 
}