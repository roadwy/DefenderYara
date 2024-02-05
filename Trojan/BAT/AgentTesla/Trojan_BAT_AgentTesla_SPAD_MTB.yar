
rule Trojan_BAT_AgentTesla_SPAD_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.SPAD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_03_0 = {02 16 9a 17 8d 21 00 00 01 13 1d 11 1d 16 1f 20 9d 11 1d 6f 90 01 03 0a 13 15 de 03 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}