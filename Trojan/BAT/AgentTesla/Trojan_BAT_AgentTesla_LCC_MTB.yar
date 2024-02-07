
rule Trojan_BAT_AgentTesla_LCC_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.LCC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,11 00 11 00 09 00 00 0a 00 "
		
	strings :
		$a_01_0 = {24 62 66 64 33 30 63 32 35 2d 66 66 63 33 2d 34 32 62 39 2d 38 63 65 38 2d 37 38 35 33 65 33 30 35 63 35 38 35 } //0a 00  $bfd30c25-ffc3-42b9-8ce8-7853e305c585
		$a_01_1 = {24 64 36 35 65 38 34 33 62 2d 62 65 30 66 2d 34 65 33 64 2d 39 38 31 34 2d 66 66 36 61 30 30 61 32 30 31 30 30 } //01 00  $d65e843b-be0f-4e3d-9814-ff6a00a20100
		$a_01_2 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //01 00  CreateInstance
		$a_01_3 = {54 6f 57 69 6e 33 32 } //01 00  ToWin32
		$a_01_4 = {43 6f 6c 6f 72 54 72 61 6e 73 6c 61 74 6f 72 } //01 00  ColorTranslator
		$a_01_5 = {47 65 74 50 69 78 65 6c } //01 00  GetPixel
		$a_01_6 = {44 65 62 75 67 67 61 62 6c 65 41 74 74 72 69 62 75 74 65 } //01 00  DebuggableAttribute
		$a_01_7 = {44 65 62 75 67 67 65 72 42 72 6f 77 73 61 62 6c 65 41 74 74 72 69 62 75 74 65 } //01 00  DebuggerBrowsableAttribute
		$a_01_8 = {44 65 62 75 67 67 65 72 4e 6f 6e 55 73 65 72 43 6f 64 65 41 74 74 72 69 62 75 74 65 } //00 00  DebuggerNonUserCodeAttribute
	condition:
		any of ($a_*)
 
}