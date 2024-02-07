
rule Trojan_BAT_AgentTesla_LPC_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.LPC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {13 04 2b 20 00 02 08 09 11 04 28 90 01 03 06 13 05 07 06 02 11 05 28 90 01 03 06 d2 9c 00 11 04 17 58 13 04 11 04 17 fe 04 13 06 11 06 2d d5 90 00 } //01 00 
		$a_01_1 = {43 6f 6c 6f 72 54 72 61 6e 73 6c 61 74 6f 72 } //00 00  ColorTranslator
	condition:
		any of ($a_*)
 
}