
rule Trojan_BAT_AgentTesla_CAO_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.CAO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 05 00 "
		
	strings :
		$a_03_0 = {16 02 8e b7 17 59 13 2d 13 23 2b 1a 02 11 23 02 11 23 91 08 11 23 07 6f 90 01 01 00 00 0a 5d 91 61 9c 11 23 17 58 13 23 11 23 11 2d 31 e0 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}