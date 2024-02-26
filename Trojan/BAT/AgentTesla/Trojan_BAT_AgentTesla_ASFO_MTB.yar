
rule Trojan_BAT_AgentTesla_ASFO_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.ASFO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 05 00 "
		
	strings :
		$a_03_0 = {0b de 03 26 de 00 07 2c 90 01 01 07 8e 69 8d 90 01 01 00 00 01 0c 16 0d 2b 90 01 01 08 09 07 09 91 06 59 d2 9c 09 17 58 0d 09 07 8e 69 32 ed 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}