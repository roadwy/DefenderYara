
rule Trojan_BAT_AgentTesla_NEJ_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NEJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 07 00 00 01 00 "
		
	strings :
		$a_01_0 = {33 62 30 65 62 37 36 33 2d 32 66 33 66 2d 34 35 39 62 2d 61 38 37 62 2d 37 36 35 35 61 32 35 63 30 62 36 35 } //02 00 
		$a_01_1 = {4b 69 6e 6f 6d 61 6e 69 61 6b 20 4c 69 62 72 61 72 79 } //02 00 
		$a_01_2 = {4b 6f 6d 65 64 69 61 52 6f 6d 61 6e 74 79 63 7a 6e 61 } //02 00 
		$a_01_3 = {46 75 6c 6c 49 6e 66 6f 57 79 73 7a 75 6b 61 6a } //01 00 
		$a_01_4 = {41 6b 63 6a 61 } //01 00 
		$a_01_5 = {57 6f 6a 65 6e 6e 79 } //01 00 
		$a_01_6 = {41 6e 69 6d 6f 77 61 6e 79 } //00 00 
	condition:
		any of ($a_*)
 
}