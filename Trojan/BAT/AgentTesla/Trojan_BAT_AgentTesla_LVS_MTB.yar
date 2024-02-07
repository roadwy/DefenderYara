
rule Trojan_BAT_AgentTesla_LVS_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.LVS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 0a 00 00 01 00 "
		
	strings :
		$a_01_0 = {50 4f 45 52 43 58 5f 33 31 34 32 34 } //01 00  POERCX_31424
		$a_01_1 = {50 4f 45 52 43 58 5f 33 32 31 34 } //01 00  POERCX_3214
		$a_01_2 = {50 4f 45 52 43 58 5f 34 33 36 35 35 36 } //01 00  POERCX_436556
		$a_01_3 = {50 4f 45 52 43 58 5f 35 34 39 33 36 37 35 34 } //01 00  POERCX_54936754
		$a_01_4 = {47 65 74 50 69 78 65 6c } //01 00  GetPixel
		$a_01_5 = {54 6f 57 69 6e 33 32 } //01 00  ToWin32
		$a_01_6 = {54 6f 41 72 72 61 79 } //01 00  ToArray
		$a_01_7 = {47 65 74 4d 65 74 68 6f 64 } //01 00  GetMethod
		$a_01_8 = {44 65 62 75 67 67 65 72 4e 6f 6e 55 73 65 72 43 6f 64 65 41 74 74 72 69 62 75 74 65 } //01 00  DebuggerNonUserCodeAttribute
		$a_01_9 = {44 65 62 75 67 67 61 62 6c 65 41 74 74 72 69 62 75 74 65 } //00 00  DebuggableAttribute
	condition:
		any of ($a_*)
 
}