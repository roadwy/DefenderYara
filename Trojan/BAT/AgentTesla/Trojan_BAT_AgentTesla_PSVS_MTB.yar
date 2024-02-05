
rule Trojan_BAT_AgentTesla_PSVS_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.PSVS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_03_0 = {28 14 00 00 0a 6f 90 01 01 00 00 0a 6f 90 01 01 00 00 0a 28 90 01 01 00 00 0a 6f 90 01 01 00 00 0a 28 90 01 01 00 00 0a 6f 90 01 01 00 00 0a 20 02 00 00 00 38 10 fe ff ff 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}