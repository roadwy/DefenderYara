
rule Backdoor_Win32_Bladabindi_ZA_MTB{
	meta:
		description = "Backdoor:Win32/Bladabindi.ZA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0e 00 0e 00 0e 00 00 01 00 "
		
	strings :
		$a_01_0 = {53 79 73 74 65 6d 2e 53 65 63 75 72 69 74 79 2e 43 72 79 70 74 6f 67 72 61 70 68 79 } //01 00  System.Security.Cryptography
		$a_01_1 = {43 72 79 70 74 6f 53 74 72 65 61 6d 4d 6f 64 65 } //01 00  CryptoStreamMode
		$a_01_2 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //01 00  CreateDecryptor
		$a_01_3 = {48 61 73 68 41 6c 67 6f 72 69 74 68 6d } //01 00  HashAlgorithm
		$a_01_4 = {43 6f 6d 70 72 65 73 73 53 68 65 6c 6c } //01 00  CompressShell
		$a_01_5 = {4e 74 51 75 65 72 79 49 6e 66 6f 72 6d 61 74 69 6f 6e 50 72 6f 63 65 73 73 } //01 00  NtQueryInformationProcess
		$a_01_6 = {4e 74 53 65 74 49 6e 66 6f 72 6d 61 74 69 6f 6e 50 72 6f 63 65 73 73 } //01 00  NtSetInformationProcess
		$a_01_7 = {49 73 44 65 62 75 67 67 65 72 50 72 65 73 65 6e 74 } //01 00  IsDebuggerPresent
		$a_01_8 = {4f 75 74 70 75 74 44 65 62 75 67 53 74 72 69 6e 67 } //01 00  OutputDebugString
		$a_01_9 = {67 65 74 5f 49 73 41 74 74 61 63 68 65 64 } //01 00  get_IsAttached
		$a_01_10 = {43 00 4f 00 52 00 5f 00 45 00 4e 00 41 00 42 00 4c 00 45 00 5f 00 50 00 52 00 4f 00 46 00 49 00 4c 00 49 00 4e 00 47 00 } //01 00  COR_ENABLE_PROFILING
		$a_01_11 = {50 00 72 00 6f 00 66 00 69 00 6c 00 65 00 72 00 20 00 64 00 65 00 74 00 65 00 63 00 74 00 65 00 64 00 } //01 00  Profiler detected
		$a_01_12 = {44 00 65 00 62 00 75 00 67 00 67 00 65 00 72 00 20 00 64 00 65 00 74 00 65 00 63 00 74 00 65 00 64 00 20 00 28 00 4d 00 61 00 6e 00 61 00 67 00 65 00 64 00 29 00 } //01 00  Debugger detected (Managed)
		$a_01_13 = {43 00 68 00 72 00 6f 00 6d 00 65 00 2e 00 65 00 78 00 65 00 } //00 00  Chrome.exe
	condition:
		any of ($a_*)
 
}