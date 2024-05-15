
rule Trojan_BAT_AgentTesla_RDBE_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.RDBE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_01_0 = {11 10 91 13 11 11 0f 17 58 11 08 5d 13 12 11 07 11 0f 91 11 11 61 11 07 11 12 91 59 13 13 11 13 20 00 01 00 00 58 13 14 } //00 00 
	condition:
		any of ($a_*)
 
}