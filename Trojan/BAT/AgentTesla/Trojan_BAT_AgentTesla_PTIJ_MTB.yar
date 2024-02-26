
rule Trojan_BAT_AgentTesla_PTIJ_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.PTIJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_01_0 = {28 49 00 00 0a 7e 13 00 00 04 03 04 6f 4a 00 00 0a 0a 7e 14 00 00 04 } //00 00 
	condition:
		any of ($a_*)
 
}