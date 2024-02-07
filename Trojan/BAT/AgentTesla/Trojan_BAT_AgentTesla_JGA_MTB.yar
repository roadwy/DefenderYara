
rule Trojan_BAT_AgentTesla_JGA_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.JGA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 0f 00 00 01 00 "
		
	strings :
		$a_00_0 = {82 99 06 20 01 01 12 82 f5 04 20 01 01 1c 10 07 0a 12 82 99 } //01 00 
		$a_00_1 = {50 72 6f 67 72 61 6d 73 00 00 0c 01 00 07 32 2e 33 2e 33 2e 32 00 00 47 } //01 00 
		$a_81_2 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //01 00  FromBase64String
		$a_81_3 = {44 65 66 6c 61 74 65 53 74 72 65 61 6d } //01 00  DeflateStream
		$a_81_4 = {47 65 74 48 49 4e 53 54 41 4e 43 45 } //01 00  GetHINSTANCE
		$a_81_5 = {4c 6f 61 64 4c 69 62 72 61 72 79 } //01 00  LoadLibrary
		$a_81_6 = {52 65 61 64 54 6f 45 6e 64 } //01 00  ReadToEnd
		$a_81_7 = {44 65 62 75 67 67 65 72 42 72 6f 77 73 61 62 6c 65 53 74 61 74 65 } //01 00  DebuggerBrowsableState
		$a_81_8 = {44 65 62 75 67 67 61 62 6c 65 41 74 74 72 69 62 75 74 65 } //01 00  DebuggableAttribute
		$a_81_9 = {44 65 62 75 67 67 65 72 42 72 6f 77 73 61 62 6c 65 41 74 74 72 69 62 75 74 65 } //01 00  DebuggerBrowsableAttribute
		$a_81_10 = {47 65 74 4d 65 74 68 6f 64 } //01 00  GetMethod
		$a_81_11 = {47 5a 69 70 53 74 72 65 61 6d } //01 00  GZipStream
		$a_81_12 = {44 65 62 75 67 67 65 72 48 69 64 64 65 6e 41 74 74 72 69 62 75 74 65 } //01 00  DebuggerHiddenAttribute
		$a_81_13 = {44 65 62 75 67 67 69 6e 67 4d 6f 64 65 73 } //01 00  DebuggingModes
		$a_81_14 = {44 6f 77 6e 6c 6f 61 64 53 74 72 69 6e 67 } //00 00  DownloadString
	condition:
		any of ($a_*)
 
}