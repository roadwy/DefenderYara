
rule Trojan_BAT_AgentTesla_NUO_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NUO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {57 df a2 eb 09 1f 00 00 00 fa 25 33 00 16 00 00 02 00 00 00 bb 00 00 00 57 00 00 00 c4 01 00 00 4c 04 00 00 13 02 00 00 23 00 00 00 3e 02 00 00 21 00 00 00 e2 01 00 00 01 00 00 00 01 00 00 00 95 00 00 00 20 } //01 00 
		$a_01_1 = {52 00 75 00 6e 00 5c 00 46 00 41 00 4e 00 4e 00 59 00 5f 00 4d 00 4f 00 56 00 45 00 53 00 5c 00 54 00 75 00 72 00 6e 00 31 00 34 00 35 00 2e 00 74 00 78 00 74 00 } //01 00  Run\FANNY_MOVES\Turn145.txt
		$a_01_2 = {42 61 74 63 68 52 75 6e 6e 65 72 2e 50 72 6f 70 65 72 74 69 65 } //01 00  BatchRunner.Propertie
		$a_01_3 = {39 36 30 33 36 64 64 39 64 64 30 65 } //01 00  96036dd9dd0e
		$a_01_4 = {39 64 34 37 35 39 37 34 } //00 00  9d475974
	condition:
		any of ($a_*)
 
}