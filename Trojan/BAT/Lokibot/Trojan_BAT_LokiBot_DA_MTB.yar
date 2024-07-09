
rule Trojan_BAT_LokiBot_DA_MTB{
	meta:
		description = "Trojan:BAT/LokiBot.DA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_03_0 = {07 08 9a 28 ?? ?? ?? 0a 0d 7e ?? ?? ?? 04 09 6f ?? ?? ?? 0a 00 00 08 17 d6 0c 08 07 8e 69 fe 04 13 04 11 04 2d da } //1
		$a_81_1 = {53 68 6f 70 5f 4d 61 6e 61 67 65 72 } //1 Shop_Manager
		$a_81_2 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //1 CreateInstance
		$a_81_3 = {41 63 74 69 76 61 74 6f 72 } //1 Activator
	condition:
		((#a_03_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=4
 
}
rule Trojan_BAT_LokiBot_DA_MTB_2{
	meta:
		description = "Trojan:BAT/LokiBot.DA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,19 00 19 00 0d 00 00 "
		
	strings :
		$a_81_0 = {24 35 64 33 66 36 64 61 34 2d 62 66 62 38 2d 34 30 31 61 2d 39 65 65 38 2d 62 66 34 64 33 66 64 61 30 62 32 34 } //20 $5d3f6da4-bfb8-401a-9ee8-bf4d3fda0b24
		$a_81_1 = {24 61 65 63 33 31 37 32 61 2d 30 38 32 30 2d 34 62 38 37 2d 62 66 36 31 2d 38 38 61 61 65 64 33 37 34 63 33 36 } //20 $aec3172a-0820-4b87-bf61-88aaed374c36
		$a_81_2 = {53 63 68 6f 6f 6c 42 6f 6f 6b 4d 61 6e 61 67 65 72 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 73 } //1 SchoolBookManager.Resources.resources
		$a_81_3 = {57 69 6e 4d 61 69 6e 2e 4d 79 2e 52 65 73 6f 75 72 63 65 73 } //1 WinMain.My.Resources
		$a_81_4 = {44 65 62 75 67 67 65 72 4e 6f 6e 55 73 65 72 43 6f 64 65 41 74 74 72 69 62 75 74 65 } //1 DebuggerNonUserCodeAttribute
		$a_81_5 = {44 65 62 75 67 67 65 72 42 72 6f 77 73 61 62 6c 65 41 74 74 72 69 62 75 74 65 } //1 DebuggerBrowsableAttribute
		$a_81_6 = {44 65 62 75 67 67 65 72 53 74 65 70 54 68 72 6f 75 67 68 41 74 74 72 69 62 75 74 65 } //1 DebuggerStepThroughAttribute
		$a_81_7 = {44 65 62 75 67 67 65 72 42 72 6f 77 73 61 62 6c 65 53 74 61 74 65 } //1 DebuggerBrowsableState
		$a_81_8 = {44 65 62 75 67 67 65 72 48 69 64 64 65 6e 41 74 74 72 69 62 75 74 65 } //1 DebuggerHiddenAttribute
		$a_81_9 = {44 65 62 75 67 67 61 62 6c 65 41 74 74 72 69 62 75 74 65 } //1 DebuggableAttribute
		$a_81_10 = {44 65 62 75 67 67 69 6e 67 4d 6f 64 65 73 } //1 DebuggingModes
		$a_81_11 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //1 CreateInstance
		$a_81_12 = {41 63 74 69 76 61 74 6f 72 } //1 Activator
	condition:
		((#a_81_0  & 1)*20+(#a_81_1  & 1)*20+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1+(#a_81_8  & 1)*1+(#a_81_9  & 1)*1+(#a_81_10  & 1)*1+(#a_81_11  & 1)*1+(#a_81_12  & 1)*1) >=25
 
}