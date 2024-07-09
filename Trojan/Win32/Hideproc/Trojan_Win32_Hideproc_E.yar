
rule Trojan_Win32_Hideproc_E{
	meta:
		description = "Trojan:Win32/Hideproc.E,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_00_0 = {4e 74 48 69 64 65 46 69 6c 65 4d 61 70 70 69 6e 67 } //1 NtHideFileMapping
		$a_00_1 = {48 69 64 65 50 72 6f 63 65 73 73 } //1 HideProcess
		$a_00_2 = {49 6e 73 74 61 6c 6c 48 6f 6f 6b } //1 InstallHook
		$a_00_3 = {53 65 74 57 69 6e 64 6f 77 73 48 6f 6f 6b 45 78 41 } //1 SetWindowsHookExA
		$a_02_4 = {50 6a 05 e8 6b f9 ff ff a3 ?? ?? ?? ?? c3 } //1
		$a_02_5 = {0f 94 c2 f6 da 1b d2 85 d2 74 2c 8d 45 ec 50 6a 40 6a 04 53 e8 ?? ?? ?? ?? 50 e8 ?? ?? ?? ?? 8d 45 ec 50 6a 04 8d 45 f4 50 53 e8 ?? ?? ?? ?? 50 e8 ?? ?? ?? ?? eb 08 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_02_4  & 1)*1+(#a_02_5  & 1)*1) >=6
 
}