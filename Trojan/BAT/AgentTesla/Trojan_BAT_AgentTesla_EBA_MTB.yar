
rule Trojan_BAT_AgentTesla_EBA_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.EBA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {02 08 02 08 91 03 08 03 8e 69 5d 91 08 04 03 8e 69 5d d6 04 5f 61 b4 61 9c 08 17 d6 0c } //00 00 
	condition:
		any of ($a_*)
 
}