
rule Trojan_BAT_AgentTesla_NKO_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NKO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {f2 02 f4 02 0f 03 ef 02 0c 20 2a 06 eb 02 0c 20 2a 06 0c 20 2a 06 e3 02 0c 20 2a 06 0c 20 2a 06 cd 02 cd 02 d6 02 0c 20 } //01 00 
		$a_01_1 = {02 df 02 e3 02 0c 20 2a 06 e1 02 11 03 0b 03 e5 02 06 03 eb 02 ea 02 e9 02 d5 02 f3 02 f0 02 e0 02 e6 02 f3 02 e0 02 0c 20 2a 06 df 02 00 03 } //01 00 
		$a_01_2 = {e1 02 df 02 05 03 ef 02 df 02 ef 02 eb 02 e7 02 e6 02 05 03 df 02 e2 02 df 02 15 03 11 03 e6 02 e1 02 df 02 05 03 e7 02 e1 02 df 02 05 03 e7 02 e6 02 ef } //01 00 
		$a_01_3 = {2a 06 e0 02 f8 02 e2 02 e2 02 05 03 d2 02 cd 02 cd 02 cd 02 cd 02 e0 02 0c 03 f3 02 e2 02 0c 20 2a 06 df 02 00 03 e5 02 e1 02 e0 02 12 03 df 02 ef 02 } //01 00 
		$a_01_4 = {00 58 58 58 58 58 58 58 58 58 58 58 58 58 58 58 58 58 58 58 58 58 58 00 } //00 00  堀塘塘塘塘塘塘塘塘塘塘X
	condition:
		any of ($a_*)
 
}