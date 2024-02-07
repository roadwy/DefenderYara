
rule Trojan_Win32_Amadey_RT_MTB{
	meta:
		description = "Trojan:Win32/Amadey.RT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0e 00 0e 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {61 6e 6f 6e 79 6d 6f 75 73 20 6e 61 6d 65 73 70 61 63 65 } //01 00  anonymous namespace
		$a_01_1 = {4e 74 55 6e 6d 61 70 56 69 65 77 4f 66 53 65 63 74 69 6f 6e } //01 00  NtUnmapViewOfSection
		$a_01_2 = {47 65 74 4e 61 74 69 76 65 53 79 73 74 65 6d 49 6e 66 6f } //0a 00  GetNativeSystemInfo
		$a_01_3 = {44 3a 5c 4d 6b 74 6d 70 5c 4e 4c 31 5c 52 65 6c 65 61 73 65 5c 4e 4c 31 2e 70 64 62 } //01 00  D:\Mktmp\NL1\Release\NL1.pdb
		$a_01_4 = {49 73 44 65 62 75 67 67 65 72 50 72 65 73 65 6e 74 } //01 00  IsDebuggerPresent
		$a_01_5 = {47 65 74 43 6f 6d 70 75 74 65 72 4e 61 6d 65 57 } //00 00  GetComputerNameW
	condition:
		any of ($a_*)
 
}