
rule Backdoor_Win32_Delf_IS{
	meta:
		description = "Backdoor:Win32/Delf.IS,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_00_0 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 41 70 70 20 50 61 74 68 73 5c 49 45 58 50 4c 4f 52 45 2e 45 58 45 } //01 00  Software\Microsoft\Windows\CurrentVersion\App Paths\IEXPLORE.EXE
		$a_03_1 = {6a 00 6a 00 8d 85 90 01 04 50 8b 06 83 c0 02 50 6a 00 e8 90 01 04 85 c0 75 90 01 01 8b 06 0f b6 40 01 50 6a 00 6a 00 8d 85 90 01 04 50 68 90 01 04 6a 00 e8 90 00 } //01 00 
		$a_03_2 = {89 5f 04 6a 06 6a 01 6a 02 e8 90 01 04 89 07 66 c7 44 24 04 02 00 56 e8 90 01 04 66 89 44 24 06 8b 47 04 50 e8 90 01 04 8b f0 89 74 24 08 46 75 90 01 01 8b 47 04 50 e8 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}