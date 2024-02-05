
rule Trojan_BAT_AgentTesla_PSVF_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.PSVF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_03_0 = {28 91 02 00 0a 73 bc 04 00 06 28 90 01 01 04 00 06 75 7c 00 00 1b 6f 90 01 01 02 00 0a 0b 07 14 28 90 01 01 02 00 0a 2c 11 07 20 92 37 4d a6 28 90 01 01 05 00 06 6f 90 01 01 02 00 0a 0a 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}