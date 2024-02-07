
rule Trojan_BAT_AgentTesla_DC_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.DC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,11 00 11 00 09 00 00 0a 00 "
		
	strings :
		$a_81_0 = {24 36 62 61 63 61 30 61 31 2d 31 39 36 32 2d 34 34 64 62 2d 38 37 32 36 2d 35 37 32 30 33 30 30 39 38 39 34 35 } //0a 00  $6baca0a1-1962-44db-8726-572030098945
		$a_81_1 = {24 33 66 35 37 33 61 33 64 2d 32 35 62 65 2d 34 34 34 66 2d 62 30 32 39 2d 64 30 33 65 62 64 62 39 35 64 34 36 } //01 00  $3f573a3d-25be-444f-b029-d03ebdb95d46
		$a_81_2 = {67 65 74 5f 43 75 72 72 65 6e 74 44 6f 6d 61 69 6e } //01 00  get_CurrentDomain
		$a_81_3 = {67 65 74 5f 42 6f 6f 73 74 42 61 73 73 } //01 00  get_BoostBass
		$a_81_4 = {67 65 74 5f 4e 65 78 74 54 72 61 63 6b } //01 00  get_NextTrack
		$a_81_5 = {67 65 74 5f 50 6c 61 79 } //01 00  get_Play
		$a_81_6 = {4d 65 64 69 61 43 6f 6d 6d 61 6e 64 73 } //01 00  MediaCommands
		$a_81_7 = {43 6f 6d 70 75 74 65 72 } //01 00  Computer
		$a_81_8 = {49 43 6c 6f 6e 65 61 62 6c 65 } //00 00  ICloneable
	condition:
		any of ($a_*)
 
}