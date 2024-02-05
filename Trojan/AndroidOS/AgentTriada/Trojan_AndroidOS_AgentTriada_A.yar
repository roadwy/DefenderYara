
rule Trojan_AndroidOS_AgentTriada_A{
	meta:
		description = "Trojan:AndroidOS/AgentTriada.A,SIGNATURE_TYPE_DEXHSTR_EXT,19 00 19 00 06 00 00 05 00 "
		
	strings :
		$a_01_0 = {63 72 65 61 74 65 20 74 61 62 6c 65 20 4d 75 6c 69 74 69 54 61 62 4c 65 } //05 00 
		$a_00_1 = {63 6f 6d 2e 63 6e 6d 61 69 6e 64 2e 63 67 6f } //05 00 
		$a_00_2 = {66 65 74 63 68 43 6f 64 65 55 52 4c } //05 00 
		$a_00_3 = {2f 72 65 67 2f 69 } //05 00 
		$a_00_4 = {64 6f 77 6e 6c 6f 61 64 20 73 74 61 72 74 } //05 00 
		$a_00_5 = {73 79 73 70 61 74 63 68 } //00 00 
	condition:
		any of ($a_*)
 
}