
rule Trojan_BAT_AgentTesla_JUL_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.JUL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_81_0 = {00 1d 5c 00 24 00 28 00 5b 00 5e 00 5c 00 73 00 5c 00 24 00 5d 00 2b 00 29 00 5c 00 24 00 00 c0 01 10 01 cc 00 ce 00 e9 00 c9 00 b9 00 b9 00 c5 00 b9 00 b9 00 b9 00 b9 00 bd 00 b9 00 b9 00 b9 } //01 00 
		$a_81_1 = {de 00 ed 00 df 00 ac 00 b9 00 ec 00 b9 00 e6 00 c6 00 c1 00 da 00 df 00 ba 00 cc 00 c5 00 a8 00 e0 00 ce 00 bf 00 e0 00 e8 00 db } //01 00 
		$a_81_2 = {53 6e 69 70 70 65 74 73 } //01 00 
		$a_81_3 = {46 72 6f 6d 42 61 73 65 36 34 } //01 00 
		$a_81_4 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //00 00 
	condition:
		any of ($a_*)
 
}