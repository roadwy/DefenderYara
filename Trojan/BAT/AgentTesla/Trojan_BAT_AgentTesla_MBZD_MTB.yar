
rule Trojan_BAT_AgentTesla_MBZD_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.MBZD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {07 16 16 28 03 00 00 06 16 31 01 2a 20 b1 04 00 00 28 0a 00 00 0a 08 17 58 0c 08 1b 32 d2 } //01 00 
		$a_01_1 = {28 06 00 00 0a 16 0c 2b 2a 06 28 07 00 00 0a 6f 08 00 00 0a 28 09 00 00 0a 07 16 } //00 00 
	condition:
		any of ($a_*)
 
}