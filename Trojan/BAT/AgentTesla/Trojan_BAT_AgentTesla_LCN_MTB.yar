
rule Trojan_BAT_AgentTesla_LCN_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.LCN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 0a 00 00 01 00 "
		
	strings :
		$a_01_0 = {34 39 65 32 39 30 37 61 2d 36 64 32 61 2d 34 61 34 62 2d 62 34 64 38 2d 33 35 61 65 35 39 34 36 38 66 63 36 } //01 00  49e2907a-6d2a-4a4b-b4d8-35ae59468fc6
		$a_01_1 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //01 00  CreateInstance
		$a_01_2 = {54 6f 57 69 6e 33 32 } //01 00  ToWin32
		$a_01_3 = {46 53 46 53 46 53 46 46 } //01 00  FSFSFSFF
		$a_01_4 = {52 6f 67 75 65 6c 69 6b 65 } //01 00  Roguelike
		$a_01_5 = {43 6f 6c 6f 72 54 72 61 6e 73 6c 61 74 6f 72 } //01 00  ColorTranslator
		$a_01_6 = {47 65 74 50 69 78 65 6c } //01 00  GetPixel
		$a_01_7 = {44 65 62 75 67 67 61 62 6c 65 41 74 74 72 69 62 75 74 65 } //01 00  DebuggableAttribute
		$a_01_8 = {44 65 62 75 67 67 65 72 42 72 6f 77 73 61 62 6c 65 41 74 74 72 69 62 75 74 65 } //01 00  DebuggerBrowsableAttribute
		$a_01_9 = {44 65 62 75 67 67 65 72 4e 6f 6e 55 73 65 72 43 6f 64 65 41 74 74 72 69 62 75 74 65 } //00 00  DebuggerNonUserCodeAttribute
	condition:
		any of ($a_*)
 
}