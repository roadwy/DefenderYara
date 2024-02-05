
rule Trojan_BAT_AgentTesla_PSJC_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.PSJC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_01_0 = {00 06 06 6f 3c 00 00 0a 06 6f 3d 00 00 0a 6f 3e 00 00 0a 0b 02 73 3f 00 00 0a 0c 08 07 16 73 40 00 00 0a 0d 00 02 8e 69 8d 24 00 00 01 13 04 09 11 04 16 11 04 8e 69 6f 41 00 00 0a 13 05 11 04 11 05 28 01 00 00 2b 28 02 00 00 2b 13 06 de 2c } //00 00 
	condition:
		any of ($a_*)
 
}