
rule Trojan_Win32_Emotetcrypt_FV_MTB{
	meta:
		description = "Trojan:Win32/Emotetcrypt.FV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 09 00 00 01 00 "
		
	strings :
		$a_81_0 = {44 6c 6c 52 65 67 69 73 74 65 72 53 65 72 76 65 72 } //01 00  DllRegisterServer
		$a_81_1 = {6b 65 62 61 31 63 71 73 71 36 2e 64 6c 6c } //01 00  keba1cqsq6.dll
		$a_81_2 = {43 72 65 61 74 65 54 6f 6f 6c 68 65 6c 70 33 32 53 6e 61 70 73 68 6f 74 } //01 00  CreateToolhelp32Snapshot
		$a_81_3 = {49 73 50 72 6f 63 65 73 73 6f 72 46 65 61 74 75 72 65 50 72 65 73 65 6e 74 } //01 00  IsProcessorFeaturePresent
		$a_81_4 = {49 73 44 65 62 75 67 67 65 72 50 72 65 73 65 6e 74 } //01 00  IsDebuggerPresent
		$a_81_5 = {47 65 74 43 6f 6d 6d 61 6e 64 4c 69 6e 65 41 } //01 00  GetCommandLineA
		$a_81_6 = {43 72 65 61 74 65 4d 75 74 65 78 41 } //01 00  CreateMutexA
		$a_81_7 = {44 65 6c 65 74 65 46 69 6c 65 41 } //01 00  DeleteFileA
		$a_81_8 = {53 6c 65 65 70 } //00 00  Sleep
	condition:
		any of ($a_*)
 
}