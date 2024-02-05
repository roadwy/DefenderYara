
rule Trojan_BAT_AgentTesla_QG_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.QG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_01_0 = {11 02 11 03 11 01 11 03 11 01 8e 69 5d 91 11 00 11 03 91 61 d2 9c } //00 00 
	condition:
		any of ($a_*)
 
}