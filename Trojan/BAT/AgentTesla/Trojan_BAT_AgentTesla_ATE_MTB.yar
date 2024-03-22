
rule Trojan_BAT_AgentTesla_ATE_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.ATE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 02 00 "
		
	strings :
		$a_01_0 = {13 1b 2b 1e 00 11 04 11 1b 11 04 11 1b 91 11 05 11 1b 11 05 8e 69 5d 91 61 d2 9c 00 11 1b 17 58 13 1b 11 1b 11 04 8e 69 } //01 00 
		$a_01_1 = {53 74 75 62 5c 50 72 6f 6a 65 63 74 73 5c 4a 61 62 72 65 74 5c 6f 62 6a 5c 44 65 62 75 67 5c 4a 61 62 72 65 74 2e 70 64 62 } //00 00  Stub\Projects\Jabret\obj\Debug\Jabret.pdb
	condition:
		any of ($a_*)
 
}