
rule Trojan_BAT_AgentTesla_RDAD_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.RDAD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_01_0 = {08 11 04 16 73 5d 02 00 0a 0d 09 07 6f 5e 02 00 0a 07 6f 4c 00 00 0a 13 05 } //00 00 
	condition:
		any of ($a_*)
 
}