
rule Trojan_BAT_AgentTesla_ESL_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.ESL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {fe 0c 00 00 fe 0c 01 00 93 28 90 01 03 0a fe 0e 02 00 fe 09 01 00 28 90 01 03 0a fe 0e 03 00 fe 0c 02 00 fe 0c 03 00 58 90 01 0a 58 3c 30 00 00 00 fe 0c 02 00 fe 0c 03 00 59 90 01 0a 58 3e 17 00 00 00 fe 0c 00 00 fe 0c 01 00 fe 0c 02 00 fe 0c 03 00 59 28 90 01 03 0a 9d 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}