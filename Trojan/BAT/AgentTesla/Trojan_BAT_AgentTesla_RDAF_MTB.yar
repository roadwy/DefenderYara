
rule Trojan_BAT_AgentTesla_RDAF_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.RDAF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_01_0 = {11 00 11 05 11 00 11 06 11 05 59 17 59 91 9c } //00 00 
	condition:
		any of ($a_*)
 
}