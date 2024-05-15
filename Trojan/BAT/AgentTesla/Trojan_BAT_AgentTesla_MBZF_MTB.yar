
rule Trojan_BAT_AgentTesla_MBZF_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.MBZF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {06 07 17 58 06 8e 69 5d 91 28 90 02 40 9c 07 15 58 0b 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}