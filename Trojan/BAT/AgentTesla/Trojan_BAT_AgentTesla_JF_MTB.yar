
rule Trojan_BAT_AgentTesla_JF_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.JF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_03_0 = {20 00 01 00 00 14 14 18 8d 90 01 01 00 00 01 25 16 08 a2 25 17 19 8d 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}