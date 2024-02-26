
rule Trojan_BAT_AgentTesla_PTHH_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.PTHH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_03_0 = {6f 6c 00 00 0a 0c 20 4b 47 14 a2 28 90 01 01 00 00 06 28 90 01 01 00 00 0a 20 ac 47 14 a2 28 90 01 01 00 00 06 20 00 01 00 00 14 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}