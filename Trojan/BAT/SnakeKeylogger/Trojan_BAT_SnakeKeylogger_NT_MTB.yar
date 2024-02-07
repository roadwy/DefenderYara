
rule Trojan_BAT_SnakeKeylogger_NT_MTB{
	meta:
		description = "Trojan:BAT/SnakeKeylogger.NT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {24 61 62 63 34 63 65 33 63 2d 32 63 37 62 2d 34 32 62 65 2d 62 33 64 36 2d 32 64 30 31 62 63 64 33 62 66 36 66 } //01 00  $abc4ce3c-2c7b-42be-b3d6-2d01bcd3bf6f
		$a_01_1 = {46 69 6e 61 6c 50 72 6f 6a 65 63 74 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 73 } //01 00  FinalProject.Properties.Resources.resources
		$a_01_2 = {47 65 74 54 79 70 65 } //01 00  GetType
		$a_01_3 = {44 65 62 75 67 67 65 72 4e 6f 6e 55 73 65 72 43 6f 64 65 41 74 74 72 69 62 75 74 65 } //01 00  DebuggerNonUserCodeAttribute
		$a_01_4 = {44 65 62 75 67 67 61 62 6c 65 41 74 74 72 69 62 75 74 65 } //00 00  DebuggableAttribute
	condition:
		any of ($a_*)
 
}