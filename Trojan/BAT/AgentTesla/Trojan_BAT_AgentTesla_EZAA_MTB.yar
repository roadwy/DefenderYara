
rule Trojan_BAT_AgentTesla_EZAA_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.EZAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 05 00 "
		
	strings :
		$a_01_0 = {11 0b 91 61 11 01 11 09 91 11 06 58 11 06 5d 59 d2 9c } //00 00 
	condition:
		any of ($a_*)
 
}