
rule Trojan_BAT_AgentTesla_AI_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.AI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 02 00 "
		
	strings :
		$a_01_0 = {18 9a 1f 09 95 2d 03 16 2b 01 17 17 59 7e 0b 00 00 04 16 9a 20 db 01 00 00 95 5f 7e 0b 00 00 04 16 9a 20 e5 01 00 00 95 61 59 } //02 00 
		$a_01_1 = {19 9a 20 01 05 00 00 95 e0 95 7e 0b 00 00 04 19 9a 20 de 0c 00 00 95 61 7e 0b 00 00 04 19 9a 20 c1 0b 00 00 95 2e 03 17 2b 01 16 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_AgentTesla_AI_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.AI!MTB,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {28 14 00 00 0a 00 16 28 15 00 00 0a 00 73 77 00 00 06 0a 2a } //01 00 
		$a_01_1 = {28 e6 00 00 0a 28 81 00 00 06 28 7a 00 00 06 6f e7 00 00 0a 0a 02 06 28 78 00 00 06 0b 02 07 28 7b 00 00 06 00 16 28 e8 00 00 0a 00 16 0c 2b 00 08 2a } //00 00 
	condition:
		any of ($a_*)
 
}