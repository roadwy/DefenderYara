
rule Trojan_BAT_AgentTesla_MRM_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.MRM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {03 72 46 a0 02 70 6f 90 01 04 0a 06 14 18 8d 90 01 04 25 16 7e 90 01 04 a2 25 17 72 90 01 04 a2 6f 90 01 04 26 2a 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}