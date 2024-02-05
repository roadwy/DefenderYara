
rule Trojan_BAT_AgentTesla_NXR_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NXR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {51 00 75 00 65 00 73 00 74 00 4b 00 69 00 6e 00 67 00 64 00 6f 00 6d 00 00 1b 2e 00 57 00 6f 00 72 00 6b 00 65 00 72 00 48 00 65 00 6c 00 70 00 65 00 72 } //00 00 
	condition:
		any of ($a_*)
 
}