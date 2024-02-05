
rule Trojan_BAT_AgentTesla_ABRP_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.ABRP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 05 00 "
		
	strings :
		$a_01_0 = {03 18 fe 01 13 08 11 08 2c 31 02 8e 69 17 da 13 09 16 13 0a 2b 1b 02 11 0a 91 16 fe 01 13 0b 11 0b 2c 07 02 11 0a 1f 41 9c 00 00 11 0a 17 d6 13 0a 11 0a 11 09 31 df } //00 00 
	condition:
		any of ($a_*)
 
}