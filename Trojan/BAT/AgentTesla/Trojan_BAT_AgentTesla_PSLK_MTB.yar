
rule Trojan_BAT_AgentTesla_PSLK_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.PSLK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 02 00 "
		
	strings :
		$a_01_0 = {72 01 00 00 70 28 08 00 00 06 0a dd 03 00 00 00 26 de ec 06 2a } //02 00 
		$a_01_1 = {28 05 00 00 0a 02 6f 06 00 00 0a 2a } //00 00 
	condition:
		any of ($a_*)
 
}