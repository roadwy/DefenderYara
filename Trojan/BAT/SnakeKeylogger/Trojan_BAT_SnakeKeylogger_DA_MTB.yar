
rule Trojan_BAT_SnakeKeylogger_DA_MTB{
	meta:
		description = "Trojan:BAT/SnakeKeylogger.DA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1b 00 1b 00 09 00 00 "
		
	strings :
		$a_81_0 = {24 34 37 38 63 38 63 62 30 2d 31 34 35 62 2d 34 63 32 33 2d 61 37 31 61 2d 34 33 32 61 37 38 63 61 61 34 64 62 } //20 $478c8cb0-145b-4c23-a71a-432a78caa4db
		$a_81_1 = {44 65 62 75 67 67 65 72 4e 6f 6e 55 73 65 72 43 6f 64 65 41 74 74 72 69 62 75 74 65 } //1 DebuggerNonUserCodeAttribute
		$a_81_2 = {43 61 6c 63 75 6c 61 74 6f 72 5f 32 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 } //1 Calculator_2.Properties.Resources
		$a_81_3 = {44 65 62 75 67 67 65 72 42 72 6f 77 73 61 62 6c 65 53 74 61 74 65 } //1 DebuggerBrowsableState
		$a_81_4 = {44 65 62 75 67 67 61 62 6c 65 41 74 74 72 69 62 75 74 65 } //1 DebuggableAttribute
		$a_81_5 = {44 65 62 75 67 67 65 72 42 72 6f 77 73 61 62 6c 65 41 74 74 72 69 62 75 74 65 } //1 DebuggerBrowsableAttribute
		$a_81_6 = {44 65 62 75 67 67 69 6e 67 4d 6f 64 65 73 } //1 DebuggingModes
		$a_81_7 = {67 65 74 5f 49 6e 73 74 61 6e 63 65 } //1 get_Instance
		$a_81_8 = {47 65 74 44 6f 6d 61 69 6e } //1 GetDomain
	condition:
		((#a_81_0  & 1)*20+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1+(#a_81_8  & 1)*1) >=27
 
}