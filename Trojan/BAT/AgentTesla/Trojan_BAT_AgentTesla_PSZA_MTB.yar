
rule Trojan_BAT_AgentTesla_PSZA_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.PSZA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_03_0 = {fe 0c 03 00 28 90 01 01 00 00 0a fe 0c 02 00 6f c0 01 00 06 6f 2f 00 00 0a 7d 3c 01 00 04 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}