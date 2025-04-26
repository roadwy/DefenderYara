
rule Trojan_BAT_AgentTesla_EE_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.EE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_02_0 = {0a 0b 16 0c 2b 13 00 07 08 07 08 91 20 ?? ?? ?? 00 59 d2 9c 00 08 17 58 0c 08 07 8e 69 fe 04 0d 09 2d e3 } //10
	condition:
		((#a_02_0  & 1)*10) >=10
 
}
rule Trojan_BAT_AgentTesla_EE_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.EE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,18 00 18 00 0b 00 00 "
		
	strings :
		$a_81_0 = {24 32 61 36 66 66 31 64 33 2d 30 34 63 63 2d 34 32 62 36 2d 61 30 34 64 2d 63 66 31 36 33 63 32 30 61 65 37 66 } //20 $2a6ff1d3-04cc-42b6-a04d-cf163c20ae7f
		$a_81_1 = {53 74 75 64 79 54 6f 6f 6c 2e 53 74 75 64 79 54 6f 6f 6c 2e 72 65 73 6f 75 72 63 65 73 } //1 StudyTool.StudyTool.resources
		$a_81_2 = {44 65 62 75 67 67 65 72 4e 6f 6e 55 73 65 72 43 6f 64 65 41 74 74 72 69 62 75 74 65 } //1 DebuggerNonUserCodeAttribute
		$a_81_3 = {44 65 62 75 67 67 65 72 42 72 6f 77 73 61 62 6c 65 41 74 74 72 69 62 75 74 65 } //1 DebuggerBrowsableAttribute
		$a_81_4 = {44 65 62 75 67 67 65 72 53 74 65 70 54 68 72 6f 75 67 68 41 74 74 72 69 62 75 74 65 } //1 DebuggerStepThroughAttribute
		$a_81_5 = {44 65 62 75 67 67 65 72 42 72 6f 77 73 61 62 6c 65 53 74 61 74 65 } //1 DebuggerBrowsableState
		$a_81_6 = {44 65 62 75 67 67 65 72 48 69 64 64 65 6e 41 74 74 72 69 62 75 74 65 } //1 DebuggerHiddenAttribute
		$a_81_7 = {44 65 62 75 67 67 61 62 6c 65 41 74 74 72 69 62 75 74 65 } //1 DebuggableAttribute
		$a_81_8 = {44 65 62 75 67 67 69 6e 67 4d 6f 64 65 73 } //1 DebuggingModes
		$a_81_9 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //1 CreateInstance
		$a_81_10 = {41 63 74 69 76 61 74 6f 72 } //1 Activator
	condition:
		((#a_81_0  & 1)*20+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1+(#a_81_8  & 1)*1+(#a_81_9  & 1)*1+(#a_81_10  & 1)*1) >=24
 
}
rule Trojan_BAT_AgentTesla_EE_MTB_3{
	meta:
		description = "Trojan:BAT/AgentTesla.EE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,17 00 17 00 0d 00 00 "
		
	strings :
		$a_01_0 = {24 46 45 31 39 45 32 45 35 2d 43 34 33 45 2d 34 35 34 37 2d 42 46 35 32 2d 43 31 46 32 45 39 33 41 42 46 31 42 } //20 $FE19E2E5-C43E-4547-BF52-C1F2E93ABF1B
		$a_81_1 = {24 33 34 36 32 36 61 33 64 2d 39 62 61 30 2d 34 37 34 34 2d 61 39 37 61 2d 33 33 31 38 61 30 65 61 66 62 35 63 } //20 $34626a3d-9ba0-4744-a97a-3318a0eafb5c
		$a_81_2 = {24 36 65 33 62 62 62 33 63 2d 39 36 36 38 2d 34 61 33 30 2d 62 38 37 63 2d 36 32 30 32 33 63 64 39 65 62 66 65 } //20 $6e3bbb3c-9668-4a30-b87c-62023cd9ebfe
		$a_81_3 = {56 69 64 65 6f 4c 61 6e 2e 50 6c 75 67 69 6e 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 } //1 VideoLan.Plugin.Properties.Resources
		$a_81_4 = {52 65 70 6c 61 63 65 6d 65 6e 74 46 61 6c 6c 62 61 63 6b 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 } //1 ReplacementFallback.Properties.Resources
		$a_81_5 = {41 53 43 49 49 41 72 74 2e 46 6f 72 6d 31 2e 72 65 73 6f 75 72 63 65 73 } //1 ASCIIArt.Form1.resources
		$a_81_6 = {44 65 62 75 67 67 65 72 4e 6f 6e 55 73 65 72 43 6f 64 65 41 74 74 72 69 62 75 74 65 } //1 DebuggerNonUserCodeAttribute
		$a_81_7 = {44 65 62 75 67 67 65 72 42 72 6f 77 73 61 62 6c 65 41 74 74 72 69 62 75 74 65 } //1 DebuggerBrowsableAttribute
		$a_81_8 = {44 65 62 75 67 67 65 72 53 74 65 70 54 68 72 6f 75 67 68 41 74 74 72 69 62 75 74 65 } //1 DebuggerStepThroughAttribute
		$a_81_9 = {44 65 62 75 67 67 65 72 42 72 6f 77 73 61 62 6c 65 53 74 61 74 65 } //1 DebuggerBrowsableState
		$a_81_10 = {44 65 62 75 67 67 65 72 48 69 64 64 65 6e 41 74 74 72 69 62 75 74 65 } //1 DebuggerHiddenAttribute
		$a_81_11 = {44 65 62 75 67 67 61 62 6c 65 41 74 74 72 69 62 75 74 65 } //1 DebuggableAttribute
		$a_81_12 = {44 65 62 75 67 67 69 6e 67 4d 6f 64 65 73 } //1 DebuggingModes
	condition:
		((#a_01_0  & 1)*20+(#a_81_1  & 1)*20+(#a_81_2  & 1)*20+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1+(#a_81_8  & 1)*1+(#a_81_9  & 1)*1+(#a_81_10  & 1)*1+(#a_81_11  & 1)*1+(#a_81_12  & 1)*1) >=23
 
}