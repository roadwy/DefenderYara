
rule Trojan_BAT_AgentTesla_LBA_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.LBA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 01 00 "
		
	strings :
		$a_01_0 = {37 63 37 35 62 63 31 64 2d 35 37 64 33 2d 34 33 32 32 2d 38 61 37 61 2d 39 39 63 30 30 39 33 63 62 34 65 61 } //01 00  7c75bc1d-57d3-4322-8a7a-99c0093cb4ea
		$a_01_1 = {47 6f 74 74 73 63 68 61 6c 6b 73 } //01 00  Gottschalks
		$a_01_2 = {44 65 62 75 67 67 61 62 6c 65 41 74 74 72 69 62 75 74 65 } //01 00  DebuggableAttribute
		$a_01_3 = {44 65 62 75 67 67 69 6e 67 4d 6f 64 65 73 } //01 00  DebuggingModes
		$a_01_4 = {44 65 62 75 67 67 65 72 4e 6f 6e 55 73 65 72 43 6f 64 65 41 74 74 72 69 62 75 74 65 } //01 00  DebuggerNonUserCodeAttribute
		$a_01_5 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //01 00  CreateInstance
		$a_01_6 = {47 65 74 50 69 78 65 6c } //01 00  GetPixel
		$a_01_7 = {53 75 73 70 65 6e 64 4c 61 79 6f 75 74 } //00 00  SuspendLayout
	condition:
		any of ($a_*)
 
}