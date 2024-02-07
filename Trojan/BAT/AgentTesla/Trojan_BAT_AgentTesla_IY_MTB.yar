
rule Trojan_BAT_AgentTesla_IY_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.IY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 0a 00 "
		
	strings :
		$a_02_0 = {2b 4a 08 09 6f 90 01 03 0a 28 90 01 03 0a 13 04 11 04 28 90 01 03 0a 20 90 01 04 da 1f 64 da 1f 1e d6 20 90 01 03 00 da 13 05 11 05 28 90 01 03 0a 28 90 01 03 0a 13 06 07 11 06 28 90 01 03 0a 28 90 01 03 0a 0b 00 09 17 d6 0d 09 08 6f 90 01 03 0a fe 04 13 07 11 07 2d a7 90 00 } //01 00 
		$a_81_1 = {53 74 72 52 65 76 65 72 73 65 } //00 00  StrReverse
	condition:
		any of ($a_*)
 
}