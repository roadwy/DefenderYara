
rule Trojan_BAT_AgentTesla_PSYY_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.PSYY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_03_0 = {11 0c 8e 69 28 90 01 01 00 00 06 00 11 0b 11 0c 16 11 0c 8e 69 28 90 01 01 00 00 06 11 0d 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}