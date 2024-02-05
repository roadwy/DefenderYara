
rule Trojan_BAT_AgentTesla_EJN_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.EJN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {0c 06 e3 02 0c 20 0c 06 0c 20 0c 06 df 02 d5 02 df 02 ef 02 0c 20 0c 06 f4 02 0c 20 0c 06 0c 20 0c 06 e5 02 ef 02 0c 20 0c 06 0c 20 0c 06 0c 20 0c 06 0c 20 0c 06 df 02 11 03 15 03 0c 20 0c 06 df 02 e8 02 eb 02 0c 20 0c 06 df 02 e2 02 ef 02 0c 20 } //01 00 
		$a_01_1 = {00 54 6f 43 68 61 72 41 72 72 61 79 00 } //01 00 
		$a_01_2 = {00 46 72 6f 6d 42 61 73 65 36 34 } //00 00 
	condition:
		any of ($a_*)
 
}