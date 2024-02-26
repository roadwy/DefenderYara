
rule Trojan_BAT_AgentTesla_AMCF_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.AMCF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_01_0 = {07 11 09 91 13 0c 08 09 1f 16 5d 91 13 0d 11 0c 11 0d 61 13 0e 11 0e 11 0b 59 } //00 00 
	condition:
		any of ($a_*)
 
}