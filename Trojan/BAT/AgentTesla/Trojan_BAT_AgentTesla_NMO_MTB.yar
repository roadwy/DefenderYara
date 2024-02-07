
rule Trojan_BAT_AgentTesla_NMO_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NMO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 01 00 "
		
	strings :
		$a_01_0 = {24 64 30 32 36 33 32 34 38 2d 38 65 38 62 2d 34 66 64 34 2d 38 35 34 66 2d 66 30 66 35 38 36 61 61 39 31 39 65 } //01 00  $d0263248-8e8b-4fd4-854f-f0f586aa919e
		$a_80_1 = {53 68 61 72 70 53 74 72 75 63 74 75 72 65 73 2e 4d 61 69 6e 2e 53 6f 72 74 48 65 6c 70 65 72 } //SharpStructures.Main.SortHelper  01 00 
		$a_01_2 = {43 79 63 6c 65 5f 4a 75 6d 70 5f 47 61 6d 65 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 } //01 00  Cycle_Jump_Game.Properties.Resources.resource
		$a_80_3 = {49 62 67 42 54 4d 30 68 56 47 68 70 63 79 42 77 63 6d 39 6e 63 6d 46 74 49 47 4e 68 62 6d 35 76 64 43 42 69 5a 53 42 79 64 57 34 67 61 57 34 67 52 45 39 54 49 47 31 76 5a 47 55 75 44 51 30 4b 4a } //IbgBTM0hVGhpcyBwcm9ncmFtIGNhbm5vdCBiZSBydW4gaW4gRE9TIG1vZGUuDQ0KJ  01 00 
		$a_01_4 = {44 65 62 75 67 67 61 62 6c 65 41 74 74 72 69 62 75 74 65 } //01 00  DebuggableAttribute
		$a_01_5 = {44 65 62 75 67 67 65 72 4e 6f 6e 55 73 65 72 43 6f 64 65 41 74 74 72 69 62 75 74 65 } //01 00  DebuggerNonUserCodeAttribute
		$a_01_6 = {00 49 49 49 49 49 49 49 49 49 49 49 49 49 49 49 49 49 49 49 49 49 49 49 49 49 49 49 49 49 49 49 49 49 49 49 49 49 49 49 49 49 49 49 49 49 49 49 49 49 49 49 49 49 49 49 00 } //00 00 
	condition:
		any of ($a_*)
 
}