
rule Trojan_BAT_AgentTesla_PTDD_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.PTDD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_01_0 = {6f 08 00 00 0a 6f 0a 00 00 0a 06 6f 0b 00 00 0a 02 16 02 8e 69 6f 0c 00 00 0a 0b de 0a } //00 00 
	condition:
		any of ($a_*)
 
}