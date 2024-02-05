
rule Trojan_BAT_AgentTesla_MBHZ_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.MBHZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {0b 16 0c 2b 1b 07 08 06 08 91 20 90 01 04 28 90 01 01 00 00 06 28 90 01 01 00 00 0a 59 d2 9c 08 17 58 0c 08 06 8e 69 32 df 90 00 } //01 00 
		$a_01_1 = {57 17 02 0a 09 07 00 00 00 fa 01 33 00 16 00 00 01 00 00 00 } //00 00 
	condition:
		any of ($a_*)
 
}