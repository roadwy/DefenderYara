
rule Trojan_BAT_AgentTesla_MBAT_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.MBAT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 06 00 00 02 00 "
		
	strings :
		$a_01_0 = {34 44 7e 35 41 7e 39 30 4f 7e 30 33 4f 4f 4f 7e 30 34 4f 4f 4f 7e 46 46 7e 46 46 4f 4f 7e 42 } //02 00 
		$a_01_1 = {74 00 72 00 69 00 6e 00 67 00 31 00 00 00 00 00 01 fb e6 09 34 44 7e 35 41 7e 39 30 4f 7e 30 } //02 00 
		$a_01_2 = {7e 31 46 7e 42 41 7e 30 45 4f 7e 42 34 7e 30 39 7e 43 44 7e 32 31 7e 42 38 7e 30 31 7e 34 43 } //02 00 
		$a_01_3 = {4f 4f 4f 7e 34 30 7e 30 31 4f 7e 30 43 4f 4f 4f 4f 4f 4f 4f 4f 4f 4f 4f 4f 4f 4f 4f 4f 4f 4f } //01 00 
		$a_01_4 = {52 65 70 6c 61 63 65 } //01 00 
		$a_01_5 = {53 70 6c 69 74 } //00 00 
	condition:
		any of ($a_*)
 
}