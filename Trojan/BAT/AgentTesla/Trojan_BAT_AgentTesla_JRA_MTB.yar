
rule Trojan_BAT_AgentTesla_JRA_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.JRA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 01 00 "
		
	strings :
		$a_81_0 = {36 34 42 31 36 36 45 45 2d 44 37 32 31 2d 34 41 32 46 2d 39 43 37 31 2d 35 31 43 34 39 35 44 33 31 45 43 42 } //01 00  64B166EE-D721-4A2F-9C71-51C495D31ECB
		$a_81_1 = {43 68 65 63 6b 52 65 6d 6f 74 65 44 65 62 75 67 67 65 72 50 72 65 73 65 6e 74 } //01 00  CheckRemoteDebuggerPresent
		$a_81_2 = {46 61 63 74 6f 72 79 20 52 65 73 65 74 } //01 00  Factory Reset
		$a_81_3 = {44 65 62 75 67 67 61 62 6c 65 41 74 74 72 69 62 75 74 65 } //01 00  DebuggableAttribute
		$a_81_4 = {44 65 62 75 67 67 65 72 42 72 6f 77 73 61 62 6c 65 53 74 61 74 65 } //01 00  DebuggerBrowsableState
		$a_81_5 = {44 65 62 75 67 67 65 72 4e 6f 6e 55 73 65 72 43 6f 64 65 41 74 74 72 69 62 75 74 65 } //01 00  DebuggerNonUserCodeAttribute
		$a_81_6 = {44 65 62 75 67 67 65 72 42 72 6f 77 73 61 62 6c 65 41 74 74 72 69 62 75 74 65 } //00 00  DebuggerBrowsableAttribute
	condition:
		any of ($a_*)
 
}