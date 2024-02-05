
rule Trojan_BAT_AgentTesla_BZFA_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.BZFA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {06 09 07 09 07 6f 90 01 03 0a 5d 6f 90 01 03 0a 06 09 91 61 d2 9c 00 09 17 58 0d 09 06 8e 69 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}