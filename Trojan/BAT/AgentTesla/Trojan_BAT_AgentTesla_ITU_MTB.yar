
rule Trojan_BAT_AgentTesla_ITU_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.ITU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {11 04 11 05 7e e5 01 00 04 11 05 91 7e e6 01 00 04 61 d2 9c 11 05 17 58 13 05 11 05 11 04 8e 69 32 de } //00 00 
	condition:
		any of ($a_*)
 
}