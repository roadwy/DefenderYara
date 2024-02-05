
rule Trojan_BAT_AgentTesla_NEAB_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NEAB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 07 00 "
		
	strings :
		$a_01_0 = {02 6f 15 00 00 0a 0a 06 18 5b 8d 18 00 00 01 0b 16 0c 2b 18 07 08 18 5b 02 08 18 6f 16 00 00 0a 1f 10 28 17 00 00 0a 9c 08 18 58 0c 08 06 32 e4 } //03 00 
		$a_01_1 = {31 00 38 00 35 00 2e 00 32 00 31 00 36 00 2e 00 37 00 31 00 2e 00 31 00 32 00 30 00 } //00 00 
	condition:
		any of ($a_*)
 
}