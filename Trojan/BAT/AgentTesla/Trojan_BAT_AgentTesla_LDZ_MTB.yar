
rule Trojan_BAT_AgentTesla_LDZ_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.LDZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 01 00 "
		
	strings :
		$a_01_0 = {24 36 33 39 38 36 33 33 64 2d 61 37 65 39 2d 34 34 30 33 2d 62 32 37 30 2d 31 33 65 66 39 37 66 62 63 64 32 62 } //01 00  $6398633d-a7e9-4403-b270-13ef97fbcd2b
		$a_01_1 = {47 65 74 50 69 78 65 6c } //01 00  GetPixel
		$a_01_2 = {54 6f 57 69 6e 33 32 } //01 00  ToWin32
		$a_01_3 = {43 6f 6c 6f 72 54 72 61 6e 73 6c 61 74 6f 72 } //01 00  ColorTranslator
		$a_01_4 = {44 65 62 75 67 67 61 62 6c 65 41 74 74 72 69 62 75 74 65 } //01 00  DebuggableAttribute
		$a_01_5 = {44 65 62 75 67 67 65 72 42 72 6f 77 73 61 62 6c 65 41 74 74 72 69 62 75 74 65 } //01 00  DebuggerBrowsableAttribute
		$a_01_6 = {44 65 62 75 67 67 65 72 4e 6f 6e 55 73 65 72 43 6f 64 65 41 74 74 72 69 62 75 74 65 } //00 00  DebuggerNonUserCodeAttribute
	condition:
		any of ($a_*)
 
}