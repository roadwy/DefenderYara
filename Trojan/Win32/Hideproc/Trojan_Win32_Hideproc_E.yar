
rule Trojan_Win32_Hideproc_E{
	meta:
		description = "Trojan:Win32/Hideproc.E,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_00_0 = {4e 74 48 69 64 65 46 69 6c 65 4d 61 70 70 69 6e 67 } //01 00  NtHideFileMapping
		$a_00_1 = {48 69 64 65 50 72 6f 63 65 73 73 } //01 00  HideProcess
		$a_00_2 = {49 6e 73 74 61 6c 6c 48 6f 6f 6b } //01 00  InstallHook
		$a_00_3 = {53 65 74 57 69 6e 64 6f 77 73 48 6f 6f 6b 45 78 41 } //01 00  SetWindowsHookExA
		$a_02_4 = {50 6a 05 e8 6b f9 ff ff a3 90 01 04 c3 90 00 } //01 00 
		$a_02_5 = {0f 94 c2 f6 da 1b d2 85 d2 74 2c 8d 45 ec 50 6a 40 6a 04 53 e8 90 01 04 50 e8 90 01 04 8d 45 ec 50 6a 04 8d 45 f4 50 53 e8 90 01 04 50 e8 90 01 04 eb 08 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}