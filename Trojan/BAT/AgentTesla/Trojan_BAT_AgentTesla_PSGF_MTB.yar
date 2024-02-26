
rule Trojan_BAT_AgentTesla_PSGF_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.PSGF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 05 00 "
		
	strings :
		$a_03_0 = {03 28 f3 00 00 0a 20 6e ba fb 42 28 6b 02 00 06 6f 90 01 03 0a 73 90 01 03 0a 0c 02 28 90 01 03 0a 73 90 01 03 0a 0d 73 90 01 03 0a 0a 06 08 06 6f 90 01 03 0a 1e 5b 6f 90 01 03 0a 6f 90 01 03 0a 06 09 28 1b 01 00 06 6f 90 01 03 0a 06 06 6f 90 01 03 0a 06 6f 90 01 03 0a 6f 90 01 03 0a 13 04 09 11 04 16 73 31 01 00 0a 13 05 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}