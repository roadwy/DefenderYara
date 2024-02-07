
rule Worm_Win32_Scrolo_A{
	meta:
		description = "Worm:Win32/Scrolo.A,SIGNATURE_TYPE_PEHSTR_EXT,1d 00 1b 00 08 00 00 05 00 "
		
	strings :
		$a_01_0 = {4e 76 43 65 6e 74 65 72 2e 6c 6e 6b } //05 00  NvCenter.lnk
		$a_01_1 = {57 49 4e 44 4f 57 53 5c 73 79 73 74 65 6d 5c 73 65 72 76 69 73 65 } //05 00  WINDOWS\system\servise
		$a_01_2 = {57 49 4e 44 4f 57 53 5c 73 79 73 74 65 6d 33 32 5c 64 65 62 2e 73 79 73 } //01 00  WINDOWS\system32\deb.sys
		$a_01_3 = {53 68 6f 77 53 75 70 65 72 48 69 64 64 65 6e } //01 00  ShowSuperHidden
		$a_01_4 = {48 69 64 65 46 69 6c 65 45 78 74 } //01 00  HideFileExt
		$a_01_5 = {4e 6f 46 6f 6c 64 65 72 4f 70 74 69 6f 6e 73 } //01 00  NoFolderOptions
		$a_01_6 = {44 69 73 61 62 6c 65 54 61 73 6b 4d 67 72 } //0a 00  DisableTaskMgr
		$a_01_7 = {6a 09 e8 25 d4 fe ff a8 01 74 13 68 05 00 04 00 6a 00 68 f0 97 41 00 e8 9c d4 fe ff } //00 00 
	condition:
		any of ($a_*)
 
}