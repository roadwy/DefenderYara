
rule Trojan_BAT_AgentTesla_NEAF_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NEAF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 02 00 00 0a 00 "
		
	strings :
		$a_01_0 = {11 05 6f 48 00 00 0a 25 26 13 0a 11 0a 6f 49 00 00 0a 25 26 13 0b 11 0a 6f 4a 00 00 0a 25 26 26 11 0a 6f 4a 00 00 0a 25 26 28 1b 00 00 06 25 26 13 0c 11 0a } //05 00 
		$a_01_1 = {4e 45 57 44 52 49 4f 44 } //00 00  NEWDRIOD
	condition:
		any of ($a_*)
 
}