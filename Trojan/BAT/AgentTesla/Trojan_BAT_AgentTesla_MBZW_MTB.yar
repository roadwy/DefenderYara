
rule Trojan_BAT_AgentTesla_MBZW_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.MBZW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {5d 91 61 07 08 17 58 07 8e 69 5d 91 59 20 00 01 00 00 58 } //00 00 
	condition:
		any of ($a_*)
 
}