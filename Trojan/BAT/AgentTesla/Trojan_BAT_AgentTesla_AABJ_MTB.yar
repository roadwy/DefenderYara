
rule Trojan_BAT_AgentTesla_AABJ_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.AABJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 02 00 "
		
	strings :
		$a_03_0 = {13 05 1a 8d 90 01 01 00 00 01 25 16 11 04 a2 25 17 7e 90 01 01 00 00 0a a2 25 18 07 a2 25 19 17 8c 90 01 01 00 00 01 a2 13 06 11 05 08 6f 90 01 01 00 00 0a 09 20 00 01 00 00 14 14 90 00 } //01 00 
		$a_01_1 = {62 34 64 37 36 31 31 64 2d 38 38 31 64 2d 34 31 64 64 2d 62 65 37 62 2d 34 36 30 61 35 35 30 65 65 64 61 63 } //00 00  b4d7611d-881d-41dd-be7b-460a550eedac
	condition:
		any of ($a_*)
 
}