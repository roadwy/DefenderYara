
rule SoftwareBundler_Win32_Pokavampo{
	meta:
		description = "SoftwareBundler:Win32/Pokavampo,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {63 6c 6f 75 64 66 72 6f 6e 74 2e 6e 65 74 2f 57 69 6e 43 68 65 63 6b 53 65 74 75 70 2e 65 78 65 00 } //01 00 
		$a_01_1 = {57 6d 69 49 6e 73 70 65 63 74 6f 72 2e 64 6c 6c 00 } //01 00 
		$a_01_2 = {26 70 72 3d 76 6f } //00 00  &pr=vo
	condition:
		any of ($a_*)
 
}
rule SoftwareBundler_Win32_Pokavampo_2{
	meta:
		description = "SoftwareBundler:Win32/Pokavampo,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 55 6e 69 6e 73 74 61 6c 6c 5c 77 69 6e 63 68 65 63 6b } //01 00  Software\Microsoft\Windows\CurrentVersion\Uninstall\wincheck
		$a_01_1 = {3f 41 55 54 68 61 6e 6b 5f 79 6f 75 40 44 65 66 69 6e 65 5f 74 68 65 5f 73 79 6d 62 6f 6c 5f 5f 41 54 4c 5f 4d 49 58 45 44 40 40 } //01 00  ?AUThank_you@Define_the_symbol__ATL_MIXED@@
		$a_01_2 = {3f 41 56 49 45 78 70 6c 6f 72 65 72 55 49 41 75 74 6f 6d 61 74 69 6f 6e 40 40 } //01 00  ?AVIExplorerUIAutomation@@
		$a_01_3 = {63 00 6f 00 6e 00 74 00 65 00 78 00 74 00 2e 00 64 00 6f 00 77 00 6e 00 6c 00 6f 00 61 00 64 00 2d 00 61 00 70 00 2e 00 63 00 6f 00 6d 00 3a 00 35 00 35 00 35 00 35 00 2f 00 6d 00 74 00 61 00 } //00 00  context.download-ap.com:5555/mta
	condition:
		any of ($a_*)
 
}