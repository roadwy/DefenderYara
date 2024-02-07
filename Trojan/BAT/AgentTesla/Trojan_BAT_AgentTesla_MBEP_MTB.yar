
rule Trojan_BAT_AgentTesla_MBEP_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.MBEP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {0a 0b 06 16 73 90 01 01 00 00 0a 0c 08 07 7e 90 01 01 02 00 04 28 90 01 01 03 00 06 00 03 07 7e 90 01 01 02 00 04 90 00 } //01 00 
		$a_01_1 = {32 33 32 61 32 35 65 66 62 39 34 37 } //00 00  232a25efb947
	condition:
		any of ($a_*)
 
}