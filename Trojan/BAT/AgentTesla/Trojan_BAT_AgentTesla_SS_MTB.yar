
rule Trojan_BAT_AgentTesla_SS_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.SS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {11 04 11 05 09 11 05 09 8e 69 5d 91 06 11 05 91 61 d2 9c 11 05 17 58 13 05 11 05 06 8e 69 32 e0 } //00 00 
	condition:
		any of ($a_*)
 
}