
rule Trojan_BAT_AgentTesla_NVG_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NVG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 07 00 00 0a 00 "
		
	strings :
		$a_01_0 = {24 62 63 35 38 35 30 64 63 2d 38 64 30 35 2d 34 66 64 38 2d 39 32 66 66 2d 36 32 64 65 30 64 66 62 38 34 36 36 } //0a 00  $bc5850dc-8d05-4fd8-92ff-62de0dfb8466
		$a_01_1 = {24 31 30 37 37 37 66 64 34 2d 63 34 30 61 2d 34 64 33 65 2d 39 63 65 36 2d 62 64 38 65 38 31 33 39 65 32 35 34 } //01 00  $10777fd4-c40a-4d3e-9ce6-bd8e8139e254
		$a_01_2 = {47 65 74 50 69 78 65 6c } //01 00  GetPixel
		$a_01_3 = {43 6f 6c 6f 72 54 72 61 6e 73 6c 61 74 6f 72 } //01 00  ColorTranslator
		$a_01_4 = {54 6f 57 69 6e 33 32 } //01 00  ToWin32
		$a_01_5 = {44 65 62 75 67 67 61 62 6c 65 41 74 74 72 69 62 75 74 65 } //01 00  DebuggableAttribute
		$a_01_6 = {44 65 62 75 67 67 65 72 4e 6f 6e 55 73 65 72 43 6f 64 65 41 74 74 72 69 62 75 74 65 } //00 00  DebuggerNonUserCodeAttribute
	condition:
		any of ($a_*)
 
}