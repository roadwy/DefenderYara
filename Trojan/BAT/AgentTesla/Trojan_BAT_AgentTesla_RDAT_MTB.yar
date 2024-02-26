
rule Trojan_BAT_AgentTesla_RDAT_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.RDAT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_03_0 = {13 0f 11 0c 11 0f 6f 90 01 04 00 00 11 0d 18 58 13 0d 11 0d 11 0b 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}