
rule Trojan_BAT_AgentTesla_KAAY_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.KAAY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 05 00 "
		
	strings :
		$a_03_0 = {03 04 61 05 59 20 00 90 01 01 00 00 58 2a 90 00 } //05 00 
		$a_01_1 = {03 8e 69 0a 03 04 17 58 06 5d 91 2a } //00 00 
	condition:
		any of ($a_*)
 
}