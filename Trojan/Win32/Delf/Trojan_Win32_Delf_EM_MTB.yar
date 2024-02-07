
rule Trojan_Win32_Delf_EM_MTB{
	meta:
		description = "Trojan:Win32/Delf.EM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,12 00 12 00 06 00 00 03 00 "
		
	strings :
		$a_81_0 = {56 69 61 62 6c 65 20 53 6f 6c 75 74 69 6f 6e 2e 70 63 72 } //03 00  Viable Solution.pcr
		$a_81_1 = {4c 6f 61 64 4b 65 79 62 6f 61 72 64 4c 61 79 6f 75 74 41 } //03 00  LoadKeyboardLayoutA
		$a_81_2 = {41 63 63 65 73 73 20 76 69 6f 6c 61 74 69 6f 6e 20 61 74 20 61 64 64 72 65 73 73 } //03 00  Access violation at address
		$a_81_3 = {4b 65 79 44 65 73 63 38 65 41 } //03 00  KeyDesc8eA
		$a_81_4 = {47 6c 79 70 68 2e 44 61 74 61 } //03 00  Glyph.Data
		$a_81_5 = {41 75 74 6f 48 6f 74 6b 65 79 73 } //00 00  AutoHotkeys
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Delf_EM_MTB_2{
	meta:
		description = "Trojan:Win32/Delf.EM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {61 6e 74 69 64 65 62 75 67 67 65 72 73 } //01 00  antidebuggers
		$a_01_1 = {61 6e 74 69 76 69 72 74 75 61 6c 73 } //01 00  antivirtuals
		$a_01_2 = {4e 79 4f 57 42 30 62 33 35 78 58 57 56 74 5a 32 6b } //01 00  NyOWB0b35xXWVtZ2k
		$a_01_3 = {44 43 50 62 61 73 65 36 34 } //01 00  DCPbase64
		$a_01_4 = {42 41 6e 74 69 52 65 76 65 72 73 4d 6f 64 } //01 00  BAntiReversMod
		$a_01_5 = {4a 58 49 7a 52 53 61 46 56 63 4f 69 51 69 49 31 45 36 4a 46 56 44 53 6b 34 79 54 33 74 30 56 44 46 77 54 48 56 6d 53 6e } //00 00  JXIzRSaFVcOiQiI1E6JFVDSk4yT3t0VDFwTHVmSn
	condition:
		any of ($a_*)
 
}