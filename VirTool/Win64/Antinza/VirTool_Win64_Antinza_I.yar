
rule VirTool_Win64_Antinza_I{
	meta:
		description = "VirTool:Win64/Antinza.I,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {41 00 67 00 65 00 6e 00 74 00 2e 00 50 00 72 00 6f 00 66 00 69 00 6c 00 65 00 73 00 2e 00 48 00 74 00 74 00 70 00 } //01 00  Agent.Profiles.Http
		$a_01_1 = {41 00 67 00 65 00 6e 00 74 00 2e 00 64 00 65 00 70 00 73 00 2e 00 6a 00 73 00 6f 00 6e 00 } //01 00  Agent.deps.json
		$a_01_2 = {41 00 67 00 65 00 6e 00 74 00 2e 00 4d 00 61 00 6e 00 61 00 67 00 65 00 72 00 73 00 } //01 00  Agent.Managers
		$a_01_3 = {41 00 67 00 65 00 6e 00 74 00 2e 00 43 00 72 00 79 00 70 00 74 00 6f 00 2e 00 41 00 65 00 73 00 } //01 00  Agent.Crypto.Aes
		$a_01_4 = {41 00 67 00 65 00 6e 00 74 00 2e 00 4d 00 6f 00 64 00 65 00 6c 00 73 00 } //00 00  Agent.Models
	condition:
		any of ($a_*)
 
}