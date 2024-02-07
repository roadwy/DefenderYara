
rule TrojanDownloader_Win32_Delf_KW{
	meta:
		description = "TrojanDownloader:Win32/Delf.KW,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_00_0 = {5b 48 4b 45 59 5f 4c 4f 43 41 4c 5f 4d 41 43 48 49 4e 45 5c 53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e 5d } //01 00  [HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run]
		$a_00_1 = {73 68 61 72 65 64 61 70 70 2e 72 65 67 } //01 00  sharedapp.reg
		$a_00_2 = {72 65 67 65 64 69 74 20 2f 73 20 } //01 00  regedit /s 
		$a_00_3 = {22 53 68 61 72 65 64 41 50 50 73 22 3d 22 } //01 00  "SharedAPPs"="
		$a_01_4 = {53 00 56 00 43 00 48 00 4f 00 53 00 54 00 } //00 00  SVCHOST
	condition:
		any of ($a_*)
 
}