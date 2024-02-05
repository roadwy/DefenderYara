
rule Trojan_BAT_AgentTesla_PSVD_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.PSVD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_03_0 = {06 6f 04 00 00 0a 17 3e 16 00 00 00 02 28 90 01 01 00 00 06 75 01 00 00 1b 28 90 01 01 00 00 0a 0b dd 14 00 00 00 06 0b dd 0d 00 00 00 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}