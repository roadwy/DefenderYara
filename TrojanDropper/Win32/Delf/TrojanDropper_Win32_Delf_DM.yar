
rule TrojanDropper_Win32_Delf_DM{
	meta:
		description = "TrojanDropper:Win32/Delf.DM,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 45 78 70 6c 6f 72 65 72 5c 53 68 65 6c 6c 45 78 65 63 75 74 65 48 6f 6f 6b 73 } //1 SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\ShellExecuteHooks
		$a_01_1 = {07 77 69 6e 64 6f 77 73 } //1 眇湩潤獷
		$a_03_2 = {8b f8 85 ff 0f 84 a2 00 00 00 57 a1 ?? ?? ?? ?? 50 e8 ?? ?? ?? ?? 8b d8 85 db 0f 84 8c 00 00 00 53 e8 ?? ?? ?? ?? 8b e8 85 ed 75 08 53 e8 ?? ?? ?? ?? eb 78 6a 00 68 80 00 00 00 6a 02 6a 00 6a 00 68 00 00 00 40 56 e8 ?? ?? ?? ?? 8b f0 83 fe ff 75 0f 8b c3 e8 ?? ?? ?? ?? 53 e8 ?? ?? ?? ?? eb 4a 57 a1 ?? ?? ?? ?? 50 e8 ?? ?? ?? ?? 8b f8 6a 00 8d 44 24 04 50 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}