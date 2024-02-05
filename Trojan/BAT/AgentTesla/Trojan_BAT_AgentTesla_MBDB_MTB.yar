
rule Trojan_BAT_AgentTesla_MBDB_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.MBDB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {53 00 79 00 73 00 74 00 65 00 6d 00 2e 00 41 00 63 00 74 00 69 00 76 00 61 00 74 00 6f 00 72 00 00 1d 65 00 63 00 6e 00 61 00 74 00 73 00 6e 00 49 00 65 00 74 00 61 00 65 00 72 00 43 00 } //00 00 
	condition:
		any of ($a_*)
 
}