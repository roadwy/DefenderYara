
rule Trojan_BAT_FormBook_HA_MTB{
	meta:
		description = "Trojan:BAT/FormBook.HA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 0c 00 00 01 00 "
		
	strings :
		$a_81_0 = {4e 69 6d 69 74 7a 44 45 56 } //01 00  NimitzDEV
		$a_81_1 = {49 53 65 63 74 69 6f 6e 45 6e 74 72 79 } //01 00  ISectionEntry
		$a_81_2 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //01 00  CreateInstance
		$a_81_3 = {56 69 72 74 75 61 6c 50 72 6f 74 65 63 74 } //01 00  VirtualProtect
		$a_81_4 = {72 65 67 4b 65 79 50 61 74 68 } //01 00  regKeyPath
		$a_81_5 = {44 6f 77 6e 6c 6f 61 64 4c 69 73 74 } //01 00  DownloadList
		$a_81_6 = {54 6f 57 69 6e 33 32 } //01 00  ToWin32
		$a_81_7 = {44 65 62 75 67 67 69 6e 67 4d 6f 64 65 73 } //01 00  DebuggingModes
		$a_81_8 = {41 63 74 69 76 61 74 6f 72 } //01 00  Activator
		$a_81_9 = {44 65 62 75 67 67 65 72 4e 6f 6e 55 73 65 72 43 6f 64 65 41 74 74 72 69 62 75 74 65 } //01 00  DebuggerNonUserCodeAttribute
		$a_81_10 = {44 65 62 75 67 67 61 62 6c 65 41 74 74 72 69 62 75 74 65 } //01 00  DebuggableAttribute
		$a_81_11 = {73 65 74 50 72 6f 78 79 } //00 00  setProxy
	condition:
		any of ($a_*)
 
}