
rule Trojan_BAT_AgentTesla_ICZ_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.ICZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 02 00 "
		
	strings :
		$a_01_0 = {11 07 11 01 02 11 01 91 11 03 61 d2 9c 38 } //01 00 
		$a_01_1 = {00 43 6c 61 73 73 4c 69 62 72 61 72 79 00 } //01 00  䌀慬獳楌牢牡y
		$a_81_2 = {70 6b 6f 77 65 6b 72 73 68 6b 65 6b 6c 6c } //00 00  pkowekrshkekll
	condition:
		any of ($a_*)
 
}