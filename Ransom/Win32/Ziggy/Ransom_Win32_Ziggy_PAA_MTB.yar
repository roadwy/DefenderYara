
rule Ransom_Win32_Ziggy_PAA_MTB{
	meta:
		description = "Ransom:Win32/Ziggy.PAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 0a 00 00 01 00 "
		
	strings :
		$a_01_0 = {5a 69 67 67 79 2e 50 72 6f 70 65 72 74 69 65 73 } //01 00  Ziggy.Properties
		$a_01_1 = {67 65 74 5f 5a 69 67 67 79 5f 49 6e 66 6f } //01 00  get_Ziggy_Info
		$a_01_2 = {5a 69 67 67 79 2e 43 6f 72 65 } //01 00  Ziggy.Core
		$a_01_3 = {43 72 65 61 74 65 54 6f 6f 6c 68 65 6c 70 33 32 53 6e 61 70 73 68 6f 74 } //01 00  CreateToolhelp32Snapshot
		$a_01_4 = {47 65 74 43 75 72 72 65 6e 74 50 72 6f 63 65 73 73 49 64 } //01 00  GetCurrentProcessId
		$a_01_5 = {44 00 65 00 62 00 75 00 67 00 67 00 65 00 72 00 20 00 44 00 65 00 74 00 65 00 63 00 74 00 65 00 64 00 } //01 00  Debugger Detected
		$a_01_6 = {49 73 44 65 62 75 67 67 65 72 50 72 65 73 65 6e 74 } //01 00  IsDebuggerPresent
		$a_01_7 = {43 4f 4d 20 53 75 72 72 6f 67 61 74 65 } //01 00  COM Surrogate
		$a_01_8 = {46 6f 72 63 65 52 65 6d 6f 76 65 } //01 00  ForceRemove
		$a_01_9 = {4e 6f 52 65 6d 6f 76 65 } //00 00  NoRemove
	condition:
		any of ($a_*)
 
}