
rule Trojan_BAT_AgentTesla_MVA_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.MVA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_01_0 = {07 11 09 11 0e 11 0b 59 11 07 5d d2 9c } //00 00 
	condition:
		any of ($a_*)
 
}