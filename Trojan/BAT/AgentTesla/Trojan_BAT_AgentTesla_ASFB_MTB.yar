
rule Trojan_BAT_AgentTesla_ASFB_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.ASFB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {07 09 07 8e 69 5d 91 08 09 08 28 90 01 01 00 00 06 5d 28 90 01 01 00 00 06 61 28 90 01 01 00 00 06 07 09 17 58 07 8e 69 5d 91 28 90 01 01 00 00 06 59 20 00 01 00 00 58 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}