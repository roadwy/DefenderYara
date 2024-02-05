
rule Trojan_BAT_AgentTesla_MAAA_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.MAAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {4f 50 4e 31 4c 57 5f 76 31 2e 5f 31 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 } //00 00 
	condition:
		any of ($a_*)
 
}