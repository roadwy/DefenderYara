
rule Trojan_BAT_AgentTesla_NXE_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NXE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {24 36 63 30 64 61 34 39 63 2d 66 66 65 37 2d 34 63 64 36 2d 62 30 32 65 2d 38 37 34 63 35 61 39 62 38 65 65 38 } //01 00  $6c0da49c-ffe7-4cd6-b02e-874c5a9b8ee8
		$a_01_1 = {47 61 6d 65 73 70 79 4d 61 73 74 65 72 53 65 72 76 65 72 2e 52 65 73 6f 75 72 63 65 73 } //01 00  GamespyMasterServer.Resources
		$a_01_2 = {9f b6 3f 09 1f 00 00 00 fa 25 33 00 16 00 00 01 00 00 00 c1 00 00 00 4d 00 00 00 73 01 00 00 c5 } //01 00 
		$a_01_3 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //01 00  CreateDecryptor
		$a_01_4 = {44 65 62 75 67 67 65 72 4e 6f 6e 55 73 65 72 43 6f 64 65 41 74 74 72 69 62 75 74 65 } //00 00  DebuggerNonUserCodeAttribute
	condition:
		any of ($a_*)
 
}