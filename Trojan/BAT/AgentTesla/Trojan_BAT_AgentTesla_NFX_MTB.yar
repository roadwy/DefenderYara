
rule Trojan_BAT_AgentTesla_NFX_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NFX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {20 61 02 00 00 95 61 9e 7e 09 00 00 04 1f 32 8f 08 00 00 01 25 71 08 00 00 01 7e 2e 00 00 04 19 9a 20 09 05 00 00 95 61 81 08 00 00 01 } //01 00 
		$a_01_1 = {11 05 13 05 7e 27 00 00 04 18 9a 20 e0 11 00 00 95 61 7e 27 00 00 04 18 9a 20 2b 07 00 00 95 2e 03 17 2b 01 16 58 } //01 00 
		$a_01_2 = {7e 08 00 00 04 17 9a 20 33 04 00 00 95 61 81 05 00 00 01 38 ef 01 00 00 7e 08 00 00 04 1a 9a 1e 95 7e 08 00 00 04 17 9a 20 72 01 00 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_AgentTesla_NFX_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.NFX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {1f 3b 8f 05 00 00 01 25 71 05 00 00 01 7e 25 00 00 04 1f 3a 95 61 81 05 00 00 01 38 80 00 00 00 7e 20 00 00 04 1f 3b 95 7e 25 00 00 04 20 17 01 00 00 95 33 47 7e 32 00 00 04 7e 25 00 00 04 20 f3 03 00 00 } //01 00 
		$a_01_1 = {7e 25 00 00 04 20 80 02 00 00 95 5f 7e 25 00 00 04 20 ff 00 00 00 95 61 59 81 05 00 00 01 38 d0 02 00 00 7e 20 00 00 04 1f 3b 95 7e 25 00 00 04 20 ed 01 00 00 95 33 61 7e 06 00 00 04 16 9a 17 9a 7e 20 00 00 04 1f 13 } //01 00 
		$a_01_2 = {57 94 02 28 09 02 00 00 00 fa 25 33 00 16 00 00 01 } //01 00 
		$a_01_3 = {67 65 74 5f 42 61 73 65 44 69 72 65 63 74 6f 72 79 } //00 00 
	condition:
		any of ($a_*)
 
}