
rule Trojan_BAT_AgentTesla_AAA_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.AAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 02 00 "
		
	strings :
		$a_01_0 = {16 13 0a 2b 1b 00 11 04 11 0a 08 11 0a 91 09 11 0a 09 8e 69 5d 91 61 d2 9c 00 11 0a 17 58 13 0a 11 0a 08 8e 69 fe 04 13 0b 11 0b 2d d8 } //01 00 
		$a_01_1 = {53 00 61 00 66 00 65 00 47 00 61 00 6d 00 65 00 57 00 69 00 6e 00 46 00 6f 00 72 00 6d 00 73 00 } //00 00  SafeGameWinForms
	condition:
		any of ($a_*)
 
}