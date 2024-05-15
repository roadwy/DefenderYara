
rule Trojan_BAT_AgentTesla_PTJZ_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.PTJZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_03_0 = {38 20 02 00 00 28 90 01 01 00 00 0a 7e 01 00 00 04 02 08 6f 25 00 00 0a 28 90 01 01 00 00 0a a5 11 00 00 1b 0b 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}