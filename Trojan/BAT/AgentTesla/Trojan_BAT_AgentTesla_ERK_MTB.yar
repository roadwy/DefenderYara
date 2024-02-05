
rule Trojan_BAT_AgentTesla_ERK_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.ERK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {03 04 20 00 3e 00 00 5d 03 02 20 00 3e 00 00 04 90 01 05 03 04 17 58 20 00 3e 00 00 5d 91 90 01 05 59 11 00 58 11 00 5d 90 01 05 9c 90 01 05 03 13 01 90 01 05 00 20 00 01 00 00 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}