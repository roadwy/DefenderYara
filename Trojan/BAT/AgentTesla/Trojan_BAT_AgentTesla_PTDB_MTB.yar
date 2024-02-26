
rule Trojan_BAT_AgentTesla_PTDB_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.PTDB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_03_0 = {06 72 51 00 00 70 7e 08 00 00 04 28 90 01 01 00 00 06 74 01 00 00 1b 2a 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}