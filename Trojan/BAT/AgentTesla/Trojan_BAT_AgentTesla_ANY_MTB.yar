
rule Trojan_BAT_AgentTesla_ANY_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.ANY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 02 00 00 0a 00 "
		
	strings :
		$a_03_0 = {25 16 11 04 90 01 05 a2 25 17 11 06 90 01 05 a2 25 13 09 14 14 18 90 01 05 25 16 17 9c 25 17 17 9c 25 13 0a 90 01 05 13 0b 11 0a 16 91 2d 02 90 00 } //0a 00 
		$a_03_1 = {16 9a 0b 07 90 01 05 14 90 01 05 17 90 01 05 25 16 03 a2 14 14 90 01 0a 0c 08 90 01 05 14 90 01 05 17 90 01 05 25 16 90 01 05 a2 14 14 90 01 0a 0d 19 90 01 05 25 16 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}