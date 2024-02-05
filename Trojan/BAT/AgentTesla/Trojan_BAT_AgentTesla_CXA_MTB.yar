
rule Trojan_BAT_AgentTesla_CXA_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.CXA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 05 00 "
		
	strings :
		$a_03_0 = {02 07 20 ad 04 b7 2e 28 90 01 04 6f 90 01 04 74 90 01 04 28 90 01 04 17 8d 90 01 04 25 16 1f 3d 9d 6f 90 01 04 0c 20 90 01 04 8d 90 01 04 0d 16 0a 90 00 } //05 00 
		$a_03_1 = {09 06 08 06 9a 1f 10 28 90 01 04 9c 06 17 58 0a 06 08 8e 69 fe 04 13 05 11 05 2d 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}