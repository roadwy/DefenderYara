
rule Trojan_BAT_AgentTesla_PSGL_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.PSGL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 05 00 "
		
	strings :
		$a_03_0 = {00 28 4e 00 00 0a 0a 06 72 5b 03 00 70 28 0d 00 00 06 6f 90 01 03 0a 00 06 18 6f 90 01 03 0a 00 06 18 6f 90 01 03 0a 00 06 6f 90 01 03 0a 0b 07 02 16 02 8e 69 6f 90 01 03 0a 0c 2b 00 08 2a 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}