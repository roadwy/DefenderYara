
rule Trojan_BAT_AgentTesla_MBZL_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.MBZL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {5d 91 61 28 90 01 01 01 00 0a 07 11 90 01 01 17 58 07 8e 69 5d 91 90 00 } //01 00 
		$a_01_1 = {54 00 56 00 4e 00 48 00 53 00 35 00 34 } //00 00 
	condition:
		any of ($a_*)
 
}